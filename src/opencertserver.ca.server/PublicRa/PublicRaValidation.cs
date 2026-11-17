namespace OpenCertServer.Ca.Server.PublicRa;

using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Allows anonymous certificate requests only on explicitly public CA profiles.
/// </summary>
public sealed class PublicRaValidation : IValidateCertificateRequests<PreIssuingContext>
{
    private readonly IStoreCaProfiles _profiles;
    private readonly PublicRaOptions _options;

    /// <summary>Creates the public-RA profile validator.</summary>
    public PublicRaValidation(IStoreCaProfiles profiles, PublicRaOptions options)
    {
        _profiles = profiles;
        _options = options;
    }

    /// <inheritdoc />
    public async Task<ValidationResult> Validate(
        PreIssuingContext context,
        CancellationToken cancellationToken = default)
    {
        var request = context.Request;
        var profile = context.Profile;
        var requestor = context.Requestor;

        if (requestor?.AuthenticationType != "acme")
        {
            return requestor?.IsAuthenticated == true
                ? ValidationResult.Passed
                : ValidationResult.Reject("Anonymous certificate requests must use ACME domain validation.");
        }

        if (!_options.Enabled)
        {
            return ValidationResult.Passed;
        }

        var caProfile = await _profiles.GetProfile(profile, cancellationToken).ConfigureAwait(false);
        if (!caProfile.AllowPublicEnrollment ||
            !_options.Profiles.Contains(caProfile.Name, StringComparer.OrdinalIgnoreCase))
        {
            return ValidationResult.Reject("The selected CA profile is not enabled for public enrollment.");
        }

        var validatedDnsNames = requestor.Claims
            .Where(claim => string.Equals(claim.Type, "dns", StringComparison.OrdinalIgnoreCase))
            .Select(claim => claim.Value)
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        var csrDnsNames = new List<string>();
        foreach (var extension in request.CertificateExtensions
                     .Where(extension => string.Equals(
                         extension.Oid?.Value, Oids.SubjectAltName, StringComparison.Ordinal)))
        {
            foreach (var name in new GeneralNames(extension.RawData).Names)
            {
                if (name is { Type: GeneralName.GeneralNameType.DnsName, Value: AsnString dnsName })
                {
                    csrDnsNames.Add(dnsName.Value);
                }
            }
        }

        if (validatedDnsNames.Count == 0 || csrDnsNames.Count == 0 ||
            csrDnsNames.Any(name => !validatedDnsNames.Contains(name)))
        {
            return ValidationResult.Reject("Every DNS name in a public CSR must match an identifier validated by an ACME challenge.");
        }

        return ValidationResult.Passed;
    }
}
