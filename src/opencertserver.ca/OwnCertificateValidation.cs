using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;

namespace OpenCertServer.Ca;

public sealed partial class OwnCertificateValidation : IValidateCertificateRequests
{
    private readonly IStoreCaProfiles _caProfiles;
    private readonly IStoreCertificates _certificateStore;
    private readonly ILogger _logger;

    public OwnCertificateValidation(
        IStoreCaProfiles caProfiles,
        IStoreCertificates certificateStore,
        ILogger<OwnCertificateValidation> logger)
    {
        _caProfiles = caProfiles;
        _certificateStore = certificateStore;
        _logger = logger;
    }

    public async Task<string?> Validate(
        CertificateRequest request,
        string? profile = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        CancellationToken cancellationToken = default)
    {
        if (reenrollingFrom == null)
        {
            return null;
        }

        var caProfile = await _caProfiles.GetProfile(profile, cancellationToken).ConfigureAwait(false);
        if (!IsIssuedBy(reenrollingFrom, caProfile.CertificateChain))
        {
            LogCouldNotValidateReEnrollmentFromReEnrollingFrom(reenrollingFrom.IssuerName.Name);
            return "Re-enrollment certificate is not issued by this CA";
        }

        // A certificate this CA has revoked does not renew itself. The store answers by serial number;
        // a certificate it does not know (issued before a restart of an in-memory store) is not
        // treated as revoked - the chain check above already says it is ours.
        var (_, status, _) = await _certificateStore
            .GetCertificateStatus(CertId.Create(reenrollingFrom, HashAlgorithmName.SHA256), cancellationToken)
            .ConfigureAwait(false);
        if (status == CertificateStatus.Revoked)
        {
            LogReEnrollmentFromRevokedCertificate(reenrollingFrom.GetSerialNumberString());
            return "Re-enrollment certificate is revoked";
        }

        return null;
    }

    /// <summary>
    /// Whether <paramref name="certificate"/> chains to the profile's CA certificates, i.e. was
    /// signed by one of their keys. Comparing the issuer name is not enough: any self-signed
    /// certificate can carry the CA's name (#96).
    /// </summary>
    /// <remarks>
    /// <para>
    /// A profile may hold only its issuing intermediate, without the root. A chain then ends at
    /// that intermediate as a partial chain, and <see cref="X509Chain.Build"/> fails even though
    /// the certificate is genuine. In that case what counts is the certificate's own link: it
    /// must have been linked to one of the profile's certificates and carry no error of its own -
    /// a signature that does not verify against that certificate is reported on the certificate.
    /// </para>
    /// <para>
    /// Validity of the certificate being renewed is not checked here - this validator accepted an
    /// expired certificate before and still does (RFC 7030 §4.2.2 leaves renewal of an expired
    /// certificate to the CA's policy); callers that need more (EST via TLS, SCEP) check it
    /// themselves. Revocation is checked by the caller of this method against the store.
    /// </para>
    /// </remarks>
    private static bool IsIssuedBy(X509Certificate2 certificate, X509Certificate2Collection caCertificates)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.AddRange(caCertificates);
        chain.ChainPolicy.ExtraStore.AddRange(caCertificates);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
        if (chain.Build(certificate))
        {
            return true;
        }

        if (chain.ChainElements.Count < 2)
        {
            return false;
        }

        var issuer = chain.ChainElements[1].Certificate;
        return caCertificates.Any(ca => ca.RawData.AsSpan().SequenceEqual(issuer.RawData))
            && chain.ChainElements[0].ChainElementStatus
                .All(s => s.Status is X509ChainStatusFlags.NoError or X509ChainStatusFlags.NotTimeValid);
    }

    [LoggerMessage(LogLevel.Error, "Could not validate re-enrollment from {ReenrollingFrom}")]
    partial void LogCouldNotValidateReEnrollmentFromReEnrollingFrom(string reenrollingFrom);

    [LoggerMessage(LogLevel.Warning, "Re-enrollment refused: certificate {SerialNumber} is revoked")]
    partial void LogReEnrollmentFromRevokedCertificate(string serialNumber);
}
