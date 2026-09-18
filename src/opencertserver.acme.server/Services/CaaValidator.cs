namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.Services;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using Configuration;
using DnsClientX;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>
/// Validates whether this CA is permitted to issue a certificate for a given
/// identifier based on the CAA records published in DNS, as specified by RFC 8659.
/// </summary>
/// <remarks>
/// The processing follows RFC 8659 "Relevant Resource Record Set":
/// <list type="bullet">
/// <item>The Relevant RRset is located by climbing the DNS name tree from the
/// identifier up to (but not including) the DNS root until a CAA RRset is found.</item>
/// <item>A critical Property with an unknown or unsupported tag forbids issuance.</item>
/// <item>If the Relevant RRset contains no <c>issue</c> or <c>issuewild</c> tags,
/// CAA does not restrict issuance.</item>
/// <item><c>issue</c> restricts issuance to the listed issuer domain names;
/// an empty issuer domain name forbids issuance.</item>
/// <item><c>issuewild</c> applies only to Wildcard Domain Names and takes precedence
/// over <c>issue</c> when present.</item>
/// </list>
/// The processing also honors the RFC 8657 CAA parameter extensions:
/// <list type="bullet">
/// <item>An <c>accounturi</c> parameter only authorizes issuance for the account
/// identified by the given URI; multiple or unparsable <c>accounturi</c> parameters
/// make the property unsatisfiable.</item>
/// <item>A <c>validationmethods</c> parameter only authorizes issuance when the
/// validation method in use is listed in its comma-separated value, accepting
/// the BR 4.2.2.1.2 "ca-tbr-&lt;subsection&gt;" alternative labels (e.g.
/// <c>ca-tbr-19</c> for <c>http-01</c>) as equivalent.</item>
/// <item>Unknown parameters are ignored.</item>
/// </list>
/// </remarks>
public sealed partial class CaaValidator : ICaaValidator
{
    private const string IssueTag = "issue";
    private const string IssueWildTag = "issuewild";

    private const int IssuerCriticalFlag = 128;

    /// <summary>
    /// Maps an ACME validation method to the equivalent <c>validationmethods</c>
    /// labels, including the BR 4.2.2.1.2 "ca-tbr-&lt;subsection&gt;" alternatives
    /// (e.g. <c>ca-tbr-19</c> for the <c>http-01</c> Website-ACME method and
    /// <c>ca-tbr-7</c> for the <c>dns-01</c> DNS-Change method).
    /// </summary>
    private static readonly Dictionary<string, string[]> ValidationMethodAliases = new(StringComparer.OrdinalIgnoreCase)
    {
        ["http-01"] = ["http-01", "ca-tbr-19"],
        ["dns-01"] = ["dns-01", "ca-tbr-7"]
    };

    private readonly ILogger<CaaValidator> _logger;
    private readonly IDnsResolver _client;
    private readonly IOptions<AcmeServerOptions> _options;

    public CaaValidator(
        ILogger<CaaValidator> logger,
        IDnsResolver client,
        IOptions<AcmeServerOptions> options)
    {
        _logger = logger;
        _client = client;
        _options = options;
    }

    /// <inheritdoc />
    public async Task<AcmeError?> ValidateAsync(
        Identifier identifier,
        string? accountUri = null,
        string? validationMethod = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(identifier);

        var caaIdentities = _options.Value.CAAIdentities;
        if (caaIdentities == null || caaIdentities.Length == 0)
        {
            return null;
        }

        var fqdn = identifier.Value.Replace("*.", "", StringComparison.OrdinalIgnoreCase);
        var isWildcard = identifier.IsWildcard;
        IReadOnlyList<CaaRecord>? relevantSet;
        try
        {
            relevantSet = await LoadRelevantRecordSetAsync(fqdn, cancellationToken).ConfigureAwait(false);
        }
        catch (DnsClientException ex)
        {
            LogCaaLookupFailed(fqdn, ex.Message);
            return new AcmeError { Type = "caa", Detail = $"Could not read CAA records from DNS: {ex.Message}" };
        }

        if (relevantSet == null || relevantSet.Count == 0)
        {
            return null;
        }

        if (HasUnsupportedCriticalTag(relevantSet))
        {
            return new AcmeError
            {
                Type = "caa",
                Detail = "CAA record contains a critical property with an unsupported tag."
            };
        }

        var applicable = GetApplicableProperties(relevantSet, isWildcard);
        if (applicable.Count == 0)
        {
            return null;
        }

        if (IsAuthorized(applicable, accountUri, validationMethod))
        {
            return null;
        }

        return new AcmeError
        {
            Type = "caa",
            Detail = "CAA record does not authorize this CA to issue certificates for the identifier."
        };
    }

    /// <summary>
    /// Locates the Relevant RRset by climbing the DNS name tree from the specified
    /// FQDN until a CAA RRset is found, or until the DNS root is reached.
    /// </summary>
    private async Task<IReadOnlyList<CaaRecord>?> LoadRelevantRecordSetAsync(
        string fqdn,
        CancellationToken cancellationToken)
    {
        var domain = fqdn.TrimEnd('.');
        while (domain.Length > 0)
        {
            LogQueryingCaa(domain);
            var records = await _client
                .ResolveCaaRecordsAsync(domain, cancellationToken)
                .ConfigureAwait(false);

            if (records.Count > 0)
            {
                return records;
            }

            var separator = domain.IndexOf('.');
            if (separator < 0)
            {
                break;
            }

            domain = domain[(separator + 1)..];
        }

        return null;
    }

    /// <summary>
    /// Determines whether the Relevant RRset contains a critical Property for an
    /// unknown or unsupported tag, in which case per RFC 8659 issuance must not happen.
    /// </summary>
    private static bool HasUnsupportedCriticalTag(IEnumerable<CaaRecord> relevantSet)
    {
        foreach (var record in relevantSet)
        {
            if ((record.Flags & IssuerCriticalFlag) != IssuerCriticalFlag)
            {
                continue;
            }

            var tag = record.Tag;
            if (!string.Equals(tag, IssueTag, StringComparison.OrdinalIgnoreCase)
                && !string.Equals(tag, IssueWildTag, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// Selects the properties that apply to the request, honoring the precedence
    /// rules between <c>issue</c> and <c>issuewild</c>.
    /// </summary>
    private static List<CaaRecord> GetApplicableProperties(
        IEnumerable<CaaRecord> relevantSet,
        bool isWildcard)
    {
        var hasIssueWild = relevantSet.Any(
            r => string.Equals(r.Tag, IssueWildTag, StringComparison.OrdinalIgnoreCase));

        if (isWildcard && hasIssueWild)
        {
            return relevantSet
                .Where(r => string.Equals(r.Tag, IssueWildTag, StringComparison.OrdinalIgnoreCase))
                .ToList();
        }

        return relevantSet
            .Where(r => string.Equals(r.Tag, IssueTag, StringComparison.OrdinalIgnoreCase))
            .ToList();
    }

    /// <summary>
    /// Determines whether any applicable property authorizes this CA to issue,
    /// based on the configured <see cref="AcmeServerOptions.CAAIdentities"/> and the
    /// RFC 8657 <c>accounturi</c> and <c>validationmethods</c> parameters.
    /// </summary>
    /// <remarks>
    /// Each property is considered independently. A property authorizes issuance
    /// when its issuer domain name matches a configured CA identity and, for every
    /// RFC 8657 parameter it carries, the parameter is satisfied by the request.
    /// A property without a given parameter imposes no restriction for that axis,
    /// and a property with an invalid, unrecognized, or unsatisfied parameter never
    /// authorizes issuance (RFC 8657 §3, §4).
    /// </remarks>
    private bool IsAuthorized(
        IEnumerable<CaaRecord> applicable,
        string? accountUri,
        string? validationMethod)
    {
        var identities = _options.Value.CAAIdentities ?? [];
        var normalizedIdentities = identities
            .Where(i => !string.IsNullOrWhiteSpace(i))
            .Select(i => NormalizeDomain(i!))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        foreach (var record in applicable)
        {
            var issuerDomainName = ExtractIssuerDomainName(record.Value);
            if (issuerDomainName.Length == 0)
            {
                continue;
            }

            if (!normalizedIdentities.Contains(issuerDomainName))
            {
                continue;
            }

            var parameters = ParseParameters(record.Value);
            if (!MatchesAccountUri(parameters, accountUri)
                || !MatchesValidationMethod(parameters, validationMethod))
            {
                continue;
            }

            return true;
        }

        return false;
    }

    /// <summary>
    /// Extracts the issuer domain name from an <c>issue</c>/<c>issuewild</c> value,
    /// discarding any parameters that follow the first semicolon. An empty or
    /// malformed value yields an empty domain name, which forbids issuance.
    /// </summary>
    private static string ExtractIssuerDomainName(string value)
    {
        var issuer = value;
        var separator = issuer.IndexOf(';');
        if (separator >= 0)
        {
            issuer = issuer[..separator];
        }

        return NormalizeDomain(issuer.Trim());
    }

    /// <summary>
    /// Parses the RFC 8657 CAA parameters (<c>accounturi</c> and
    /// <c>validationmethods</c>) from an <c>issue</c>/<c>issuewild</c> value.
    /// Unknown parameters are ignored, allowing forward compatibility with
    /// future CAA parameter extensions.
    /// </summary>
    private static CaaParameters ParseParameters(string value)
    {
        var parameters = new CaaParameters();
        var separator = value.IndexOf(';');
        if (separator < 0)
        {
            return parameters;
        }

        foreach (var segment in value[(separator + 1)..].Split(';'))
        {
            var parameter = segment.Trim();
            if (parameter.Length == 0)
            {
                continue;
            }

            var equals = parameter.IndexOf('=');
            var name = equals < 0 ? parameter : parameter[..equals].Trim();
            var parameterValue = equals < 0 ? string.Empty : parameter[(equals + 1)..].Trim();

            if (string.Equals(name, "accounturi", StringComparison.OrdinalIgnoreCase))
            {
                parameters.AccountUris.Add(parameterValue);
            }
            else if (string.Equals(name, "validationmethods", StringComparison.OrdinalIgnoreCase))
            {
                parameters.ValidationMethodsSpecified = true;
                foreach (var method in parameterValue.Split(',', StringSplitOptions.TrimEntries))
                {
                    if (method.Length > 0)
                    {
                        parameters.ValidationMethods.Add(method);
                    }
                }
            }
        }

        return parameters;
    }

    /// <summary>
    /// Determines whether the request satisfies the <c>accounturi</c> restriction of
    /// a property, if any. Per RFC 8657 §3, a property without an <c>accounturi</c>
    /// parameter matches any account, a property with multiple <c>accounturi</c>
    /// parameters is unsatisfiable, and a property with an invalid or unrecognized
    /// URI is unsatisfiable.
    /// </summary>
    private static bool MatchesAccountUri(CaaParameters parameters, string? accountUri)
    {
        if (parameters.AccountUris.Count == 0)
        {
            return true;
        }

        if (parameters.AccountUris.Count > 1)
        {
            return false;
        }

        return accountUri != null
            && Uri.TryCreate(parameters.AccountUris[0], UriKind.Absolute, out var expectedUri)
            && AccountUrisMatch(accountUri, expectedUri);
    }

    /// <summary>
    /// Determines whether the request satisfies the <c>validationmethods</c>
    /// restriction of a property, if any. Per RFC 8657 §4, a property without a
    /// <c>validationmethods</c> parameter places no restriction on the method, while
    /// a property with the parameter only authorizes issuance when the method used
    /// is listed in its comma-separated value. Per BR 4.2.2.1.2, an equivalent
    /// "ca-tbr-&lt;subsection&gt;" label (e.g. <c>ca-tbr-19</c> for <c>http-01</c>)
    /// is accepted as granting permission, and labels are matched case-insensitively.
    /// </summary>
    private static bool MatchesValidationMethod(CaaParameters parameters, string? validationMethod)
    {
        if (!parameters.ValidationMethodsSpecified)
        {
            return true;
        }

        if (validationMethod == null)
        {
            return false;
        }

        var acceptedLabels = ValidationMethodAliases.TryGetValue(validationMethod, out var aliases)
            ? aliases
            : [validationMethod];

        return parameters.ValidationMethods.Any(method =>
            acceptedLabels.Contains(method, StringComparer.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Compares an account URI with a CAA <c>accounturi</c> value, treating the
    /// scheme and host as case-insensitive and ignoring a single trailing slash
    /// on the path (which carries no significance for ACME account URIs).
    /// </summary>
    private static bool AccountUrisMatch(string accountUri, Uri expectedUri)
    {
        if (!Uri.TryCreate(accountUri, UriKind.Absolute, out var actualUri))
        {
            return false;
        }

        if (!string.Equals(expectedUri.Scheme, actualUri.Scheme, StringComparison.OrdinalIgnoreCase)
            || !string.Equals(expectedUri.Host, actualUri.Host, StringComparison.OrdinalIgnoreCase)
            || expectedUri.Port != actualUri.Port)
        {
            return false;
        }

        var expectedPath = expectedUri.AbsolutePath.TrimEnd('/');
        var actualPath = actualUri.AbsolutePath.TrimEnd('/');
        return string.Equals(expectedPath, actualPath, StringComparison.Ordinal);
    }

    private static string NormalizeDomain(string domain)
        => domain.Trim().TrimEnd('.').ToLowerInvariant();

    /// <summary>
    /// Holds the RFC 8657 CAA parameters parsed from a single <c>issue</c> or
    /// <c>issuewild</c> property value.
    /// </summary>
    private sealed class CaaParameters
    {
        public List<string> AccountUris { get; } = [];

        public List<string> ValidationMethods { get; } = [];

        public bool ValidationMethodsSpecified { get; set; }
    }

    [LoggerMessage(LogLevel.Debug, "Querying CAA records for {domain}")]
    partial void LogQueryingCaa(string domain);

    [LoggerMessage(LogLevel.Warning, "CAA lookup failed for {domain}: {message}")]
    partial void LogCaaLookupFailed(string domain, string message);
}
