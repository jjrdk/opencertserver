using System.Net;

namespace OpenCertServer.Ca.Utils.Validation;

/// <summary>
/// The RFC 9525 identity-matching algorithm, extracted as a pure function so its rules — the single
/// left-most wildcard, case-insensitive DNS label comparison, octet-for-octet IP comparison, and
/// combined service-type-or-scheme-plus-DNS matching for SRV/URI — can be verified directly, without a
/// certificate or a lookup.
///
/// <para>
/// Matching is type-specific: a reference of one <see cref="ServiceIdentifierType"/> never matches a
/// presented identifier of another type.
/// </para>
/// </summary>
public static class IdentityMatcher
{
    /// <summary>
    /// Determines whether <paramref name="presented"/> is an acceptable identity for the
    /// <paramref name="reference"/> service identifier, per RFC 9525 §4.3.
    /// </summary>
    /// <param name="reference">An acceptable reference identifier.</param>
    /// <param name="presented">An identifier presented by the certificate.</param>
    /// <returns><see langword="true"/> when the presented identifier matches the reference.</returns>
    public static bool Matches(ServiceIdentity reference, ServiceIdentity presented)
    {
        // RFC 9525 §4.3 / §7.5: a reference may not be mixed across identifier types.
        if (reference.Type != presented.Type)
        {
            return false;
        }

        return reference.Type switch
        {
            ServiceIdentifierType.Dns => MatchesDns(reference.Value, presented.Value),
            ServiceIdentifierType.Ip => MatchesIp(reference.Value, presented.Value),
            ServiceIdentifierType.Srv => MatchesSrv(reference.Value, presented.Value),
            ServiceIdentifierType.Uri => MatchesUri(reference.Value, presented.Value),
            _ => false
        };
    }

    /// <summary>
    /// DNS-identifier matching (RFC 9525 §4.3.2, §6.1, §7.1): label-by-label, case-insensitive ASCII,
    /// with at most one wildcard that must be the complete left-most label and that expands to exactly
    /// one label. A presented identifier whose wildcard violates these rules is invalid and must be
    /// ignored (which, for matching purposes, is a <see langword="false"/>).
    /// </summary>
    private static bool MatchesDns(string reference, string presented)
    {
        // RFC 9525 §7.1: at most one '*' may appear, as the complete left-most label, on EITHER side.
        // A label that contains a '*' but is not exactly "*" (for example "a*", "*b", or "**") makes
        // its identifier invalid and is therefore never a match, regardless of which side it is on.
        if (HasMalformedWildcardLabel(reference) || HasMalformedWildcardLabel(presented))
        {
            return false;
        }

        var referenceLabels = SplitLabels(reference);
        var presentedLabels = SplitLabels(presented);

        // A valid comparison always needs the same number of labels on both sides. This is what
        // enforces that "wildcards over more than one label" (e.g. matching a.b.example.com with
        // *.example.com, or matching the apex example.com at all) do not happen.
        if (referenceLabels.Length != presentedLabels.Length)
        {
            return false;
        }

        for (var i = 0; i < referenceLabels.Length; i++)
        {
            // RFC 9525 §7.1: a single '*' as the complete left-most label (i == 0) is a wildcard that
            // expands to exactly one label. Because the surrounding labels already pin the rest of the
            // name, that label is skipped on WHICHEVER side carries the wildcard.
            if (i == 0 && (referenceLabels[0] == "*" || presentedLabels[0] == "*"))
            {
                continue;
            }

            if (!string.Equals(referenceLabels[i], presentedLabels[i], StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// A wildcard that is not the complete, single, left-most label — for example <c>"a*"</c>,
    /// <c>"*b"</c>, <c>".*"</c> or <c>"**"</c> — is malformed per RFC 9525 §7.1 and its identifier
    /// must be ignored (never matched).
    /// </summary>
    private static bool HasMalformedWildcardLabel(string host)
    {
        foreach (var label in SplitLabels(host))
        {
            if (label.Contains('*') && label != "*")
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// IP-identifier matching (RFC 9525 §7.4): octet-for-octet comparison. There is no partial or
    /// network matching, and an IPv4 is not matched against an IPv6-mapped address.
    /// </summary>
    private static bool MatchesIp(string reference, string presented)
    {
        if (!IPAddress.TryParse(reference, out var referenceIp) ||
            !IPAddress.TryParse(presented, out var presentedIp))
        {
            return false;
        }

        return referenceIp.AddressFamily == presentedIp.AddressFamily &&
            referenceIp.Equals(presentedIp);
    }

    /// <summary>
    /// SRV-name matching (RFC 4985 <c>SRVName</c>; RFC 9525 §4.3.3): the application service type is
    /// matched case-insensitively (the leading underscore is a delimiter) together with its own DNS
    /// name, which is compared via <see cref="MatchesDns"/>.
    /// </summary>
    private static bool MatchesSrv(string reference, string presented)
    {
        if (!SplitSrvName(reference, out var referenceService, out var referenceDomain) ||
            !SplitSrvName(presented, out var presentedService, out var presentedDomain))
        {
            return false;
        }

        // The leading underscore is a delimiter (RFC 9525 §4.3.3): "imaps" matches "_imaps".
        var referenceType = referenceService.TrimStart('_');
        var presentedType = presentedService.TrimStart('_');
        if (!string.Equals(referenceType, presentedType, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        return MatchesDns(referenceDomain, presentedDomain);
    }

    /// <summary>
    /// URI-identifier matching (RFC 9525 §7.2): only the scheme and the host are used for matching;
    /// the scheme is compared case-insensitively and the host via <see cref="MatchesDns"/>.
    /// </summary>
    private static bool MatchesUri(string reference, string presented)
    {
        if (!SplitSchemeAndHost(reference, out var referenceScheme, out var referenceHost) ||
            !SplitSchemeAndHost(presented, out var presentedScheme, out var presentedHost))
        {
            return false;
        }

        return string.Equals(referenceScheme, presentedScheme, StringComparison.OrdinalIgnoreCase) &&
            MatchesDns(referenceHost, presentedHost);
    }

    /// <summary>
    /// Splits an <c>SRVName</c> into its service type (the label before the first dot, retaining its
    /// leading underscore) and its DNS domain (the remainder).
    /// </summary>
    private static bool SplitSrvName(string srvName, out string service, out string domain)
    {
        var dot = srvName.IndexOf('.');
        if (dot <= 0 || dot == srvName.Length - 1)
        {
            service = string.Empty;
            domain = string.Empty;
            return false;
        }

        service = srvName[..dot];
        domain = srvName[(dot + 1)..];
        return true;
    }

    /// <summary>
    /// Splits a host-form URI ("<c>scheme:host</c>") into its scheme and host. Per RFC 9525 §7.2 only
    /// the scheme and host are used for matching; any path/query/fragment is discarded.
    /// </summary>
    private static bool SplitSchemeAndHost(string uri, out string scheme, out string host)
    {
        var colon = uri.IndexOf(':');
        if (colon <= 0)
        {
            scheme = string.Empty;
            host = string.Empty;
            return false;
        }

        scheme = uri[..colon];
        var hostPart = uri[(colon + 1)..];
        var end = hostPart.IndexOfAny(['/', '?', '#']);
        host = end < 0 ? hostPart : hostPart[..end];

        return !string.IsNullOrEmpty(scheme) && !string.IsNullOrEmpty(host);
    }

    /// <summary>Splits a hostname into its labels, dropping empty labels produced by leading/trailing dots.</summary>
    private static string[] SplitLabels(string host) =>
        host.Split('.', StringSplitOptions.RemoveEmptyEntries);
}