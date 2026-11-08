using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using OpenCertServer.Ca.Protocol;

namespace OpenCertServer.Ca.Server.RegistrationAuthority;

using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Enforces the configured RA identity, profile, and DNS-scope binding.
/// </summary>
public sealed class RaScopeValidator : IValidateCertificateRequests
{
    private readonly IStoreRas _store;
    private readonly RaServerOptions _options;
    private readonly IStoreCaProfiles _profiles;

    /// <summary>Creates a validator for scoped RA requests.</summary>
    public RaScopeValidator(IStoreRas store, RaServerOptions options, IStoreCaProfiles profiles)
    {
        _store = store;
        _options = options;
        _profiles = profiles;
    }

    /// <inheritdoc />
    public async Task<string?> Validate(
        CertificateRequest request,
        string? profile = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        CancellationToken cancellationToken = default)
    {
        var raId = GetSingleClaim(requestor, RaClaimTypes.RaId, out var claimError);
        if (claimError != null)
        {
            return claimError;
        }

        if (raId == null)
        {
            return null;
        }

        var caProfile = await _profiles.GetProfile(profile, cancellationToken).ConfigureAwait(false);
        var (_, scope, error) =
            await GetBindingAndScope(raId, requestor!, caProfile.Name, cancellationToken).ConfigureAwait(false);
        if (error != null)
        {
            return error;
        }

        if (!TryReadDnsNames(request, out var names))
        {
            return "An RA-scoped CSR must contain DNS subjectAltName values only.";
        }

        if (names.Any(name => !MatchesScope(name, scope!)))
        {
            return $"The CSR contains a DNS name outside the delegated scope '{scope}'.";
        }

        return null;
    }

    /// <summary>
    /// Checks whether an authenticated RA may revoke the supplied issued certificate.
    /// </summary>
    public async Task<bool> IsAuthorizedToRevoke(
        X509Certificate2 certificate,
        ClaimsIdentity? requestor,
        CancellationToken cancellationToken = default)
    {
        var raId = GetSingleClaim(requestor, RaClaimTypes.RaId, out var claimError);
        if (claimError != null || raId == null)
        {
            return false;
        }

        var (_, scope, error) =
            await GetBindingAndScope(raId, requestor!, profile: null, cancellationToken).ConfigureAwait(false);
        if (error != null)
        {
            return false;
        }

        var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().SingleOrDefault();
        return extension != null
            && TryReadDnsNames(extension.RawData, out var names)
            && names.All(name => MatchesScope(name, scope!));
    }

    private async Task<(RaBinding? Binding, string? Scope, string? Error)> GetBindingAndScope(
        string raId,
        ClaimsIdentity requestor,
        string? profile,
        CancellationToken cancellationToken)
    {
        if (!_options.AcceptRa)
        {
            return (null, null, "Registration-authority requests are disabled.");
        }

        var binding = await _store.Find(raId, cancellationToken).ConfigureAwait(false);
        if (binding == null)
        {
            return (null, null, "The authenticated registration authority has no CA binding.");
        }

        if (profile != null && !binding.AllowedProfiles.Contains(profile))
        {
            return (binding, null, $"The registration authority is not allowed to use profile '{profile}'.");
        }

        var scope = GetSingleClaim(requestor, RaClaimTypes.DelegatedSubject, out var claimError);
        if (claimError != null)
        {
            return (binding, null, claimError);
        }

        if (scope == null || !binding.AllowedScopes.Contains(scope))
        {
            return (binding, null, "The requested delegated subject is not allowed for this registration authority.");
        }

        return (binding, scope, null);
    }

    private static string? GetSingleClaim(ClaimsIdentity? identity, string claimType, out string? error)
    {
        error = null;
        var claims = identity?.FindAll(claimType).Select(claim => claim.Value).Distinct(StringComparer.Ordinal).ToArray()
                     ?? [];
        if (claims.Length > 1)
        {
            error = $"The request contains multiple conflicting '{claimType}' claims.";
            return null;
        }

        return claims.SingleOrDefault();
    }

    private static bool TryReadDnsNames(CertificateRequest request, out IReadOnlyList<string> names)
    {
        var extensions = request.CertificateExtensions
            .Where(extension => string.Equals(extension.Oid?.Value, Oids.SubjectAltName, StringComparison.Ordinal))
            .ToArray();
        if (extensions.Length != 1)
        {
            names = [];
            return false;
        }

        return TryReadDnsNames(extensions[0].RawData, out names);
    }

    private static bool TryReadDnsNames(byte[] encodedNames, out IReadOnlyList<string> names)
    {
        try
        {
            var generalNames = new GeneralNames(encodedNames);
            var dnsNames = generalNames.Names
                .Where(name => name.Type == GeneralName.GeneralNameType.DnsName)
                .Select(name => ((AsnString)name.Value).Value)
                .ToArray();
            names = dnsNames;
            return dnsNames.Length > 0 && dnsNames.Length == generalNames.Names.Length;
        }
        catch (Exception exception) when (exception is ArgumentException or System.Formats.Asn1.AsnContentException)
        {
            names = [];
            return false;
        }
    }

    private static bool MatchesScope(string name, string scope)
    {
        if (string.IsNullOrWhiteSpace(name) || name.StartsWith("*.", StringComparison.Ordinal))
        {
            return false;
        }

        try
        {
            var asciiName = new IdnMapping().GetAscii(name.TrimEnd('.'));
            var asciiScope = new IdnMapping().GetAscii(scope.TrimEnd('.'));
            return asciiName.Equals(asciiScope, StringComparison.OrdinalIgnoreCase)
                   || asciiName.EndsWith($".{asciiScope}", StringComparison.OrdinalIgnoreCase);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }
}
