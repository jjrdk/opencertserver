using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace OpenCertServer.Ca.Server.PublicRa;

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Allows anonymous certificate requests only on explicitly public CA profiles.
/// </summary>
public sealed class PublicRaValidation : IValidateCertificateRequests
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
    public async Task<string?> Validate(
        CertificateRequest request,
        string? profile = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        CancellationToken cancellationToken = default)
    {
        if (requestor?.AuthenticationType != "acme")
        {
            return requestor?.IsAuthenticated == true
                ? null
                : "Anonymous certificate requests must use ACME domain validation.";
        }

        if (!_options.Enabled)
        {
            return null;
        }

        var caProfile = await _profiles.GetProfile(profile, cancellationToken).ConfigureAwait(false);
        if (!caProfile.AllowPublicEnrollment ||
            !_options.Profiles.Contains(caProfile.Name, StringComparer.OrdinalIgnoreCase))
        {
            return "The selected CA profile is not enabled for public enrollment.";
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
                if (name.Type == GeneralName.GeneralNameType.DnsName && name.Value is AsnString dnsName)
                {
                    csrDnsNames.Add(dnsName.Value);
                }
            }
        }

        if (validatedDnsNames.Count == 0 || csrDnsNames.Count == 0 ||
            csrDnsNames.Any(name => !validatedDnsNames.Contains(name)))
        {
            return "Every DNS name in a public CSR must match an identifier validated by an ACME challenge.";
        }

        return null;
    }
}
