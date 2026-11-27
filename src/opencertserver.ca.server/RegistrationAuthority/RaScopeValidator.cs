using OpenCertServer.Ca.Protocol;

namespace OpenCertServer.Ca.Server.RegistrationAuthority;

using System.Globalization;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509;

public abstract class RaValidator
{
    private readonly IStoreRas _store;
    private readonly RaServerOptions _options;
    private readonly IStoreCaProfiles _profiles;

    protected RaValidator(IStoreRas store, RaServerOptions options, IStoreCaProfiles profiles)
    {
        _store = store;
        _options = options;
        _profiles = profiles;
    }

    protected async Task<(RaBinding? Binding, string? Scope, string? Error)> GetBindingAndScope(
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

    protected Task<CaProfile> GetProfile(string? profile, CancellationToken cancellationToken)
    {
        return _profiles.GetProfile(profile, cancellationToken);
    }

    protected static string? GetSingleClaim(ClaimsIdentity? identity, string claimType, out string? error)
    {
        error = null;
        var claims = identity?.FindAll(claimType).Select(claim => claim.Value).Distinct(StringComparer.Ordinal)
                .ToArray()
         ?? [];
        if (claims.Length > 1)
        {
            error = $"The request contains multiple conflicting '{claimType}' claims.";
            return null;
        }

        return claims.SingleOrDefault();
    }

    protected static string? TryReadCommonName(CertificateRequest request)
    {
        var commonName = request.SubjectName
            .EnumerateRelativeDistinguishedNames()
            .Where(rdn => string.Equals(rdn.GetSingleElementType().Value, Oids.CommonName, StringComparison.Ordinal))
            .Select(rdn => rdn.GetSingleElementValue())
            .FirstOrDefault();
        return string.IsNullOrWhiteSpace(commonName) ? null : commonName;
    }

    protected static bool TryReadDnsNames(CertificateRequest request, out IReadOnlyList<string> names)
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

    protected static bool TryReadDnsNames(byte[] encodedNames, out IReadOnlyList<string> names)
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

    protected static bool MatchesScope(string name, string scope)
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

/// <summary>
/// Enforces the configured RA identity, profile, and DNS-scope binding.
/// </summary>
public sealed class RaScopeValidator : RaValidator, IValidateCertificateRequests<PreIssuingContext>
{
    /// <summary>Creates a validator for scoped RA requests.</summary>
    public RaScopeValidator(IStoreRas store, RaServerOptions options, IStoreCaProfiles profiles)
        : base(store, options, profiles)
    {
    }

    /// <inheritdoc />
    public async Task<ValidationResult> Validate(
        PreIssuingContext context,
        CancellationToken cancellationToken = default)
    {
        var request = context.Request;
        var profile = context.Profile;
        var requestor = context.Requestor;

        var raId = GetSingleClaim(requestor, RaClaimTypes.RaId, out var claimError);
        if (claimError != null)
        {
            return ValidationResult.Reject(claimError);
        }

        if (raId == null)
        {
            return ValidationResult.Passed;
        }

        var caProfile = await GetProfile(profile, cancellationToken).ConfigureAwait(false);
        var (_, scope, error) =
            await GetBindingAndScope(raId, requestor!, caProfile.Name, cancellationToken).ConfigureAwait(false);
        if (error != null)
        {
            return ValidationResult.Reject(error);
        }

        if (!TryReadDnsNames(request, out var names))
        {
            return ValidationResult.Reject("An RA-scoped CSR must contain DNS subjectAltName values only.");
        }

        if (names.Any(name => !MatchesScope(name, scope!)))
        {
            return ValidationResult.Reject($"The CSR contains a DNS name outside the delegated scope '{scope}'.");
        }

        // The subject CN, when present, must also fall within the delegated scope. subjectAltName is
        // authoritative for TLS, but a mismatched CN is an audit and confusion vector and a scope gap
        // in the subject, so the RA may not carry a common name outside its delegated scope.
        var commonName = TryReadCommonName(request);
        if (commonName is { } cn && !MatchesScope(cn, scope!))
        {
            return ValidationResult.Reject(
                $"The CSR subject common name '{cn}' is outside the delegated scope '{scope}'.");
        }

        return ValidationResult.Passed;
    }
}

public sealed class RaRevocationValidator : RaValidator, IValidateCertificateRequests<RevokeContext>
{
    public RaRevocationValidator(IStoreRas store, RaServerOptions options, IStoreCaProfiles profiles)
        : base(store, options, profiles)
    {
    }

    public async Task<ValidationResult> Validate(RevokeContext context, CancellationToken cancellationToken = default)
    {
        var requestor = context.Requestor;
        var certificate = context.IssuedCertificate;
        var raId = GetSingleClaim(requestor, RaClaimTypes.RaId, out var claimError);
        if (claimError != null || raId == null)
        {
            return ValidationResult.Reject(claimError!);
        }

        var (_, scope, error) =
            await GetBindingAndScope(raId, requestor!, profile: null, cancellationToken).ConfigureAwait(false);
        if (error != null)
        {
            return ValidationResult.Reject(error);
        }

        var extension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().SingleOrDefault();
        var canRevoke = extension != null
         && TryReadDnsNames(extension.RawData, out var names)
         && names.All(name => MatchesScope(name, scope!));

        return canRevoke
            ? ValidationResult.Passed
            : ValidationResult.Reject($"The certificate contains a DNS name outside the delegated scope '{scope}'.");
    }
}
