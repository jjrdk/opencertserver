using System.Formats.Asn1;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Utils;
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
    /// Whether <paramref name="certificate"/> was signed by one of the profile's CA certificates.
    /// Comparing the issuer name is not enough: any self-signed certificate can carry the CA's
    /// name (#96). Verifying the signature directly also works when the profile contains only
    /// an intermediate and the platform chain builder cannot build a complete path to a root.
    /// Expiration and revocation are handled separately from this issuer check.
    /// </summary>
    private static bool IsIssuedBy(X509Certificate2 certificate, X509Certificate2Collection caCertificates)
    {
        foreach (var issuer in caCertificates)
        {
            if (string.Equals(certificate.IssuerName.Name, issuer.SubjectName.Name,
                    StringComparison.OrdinalIgnoreCase)
             && HasValidSignature(certificate, issuer))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasValidSignature(X509Certificate2 certificate, X509Certificate2 issuer)
    {
        var certificateReader = new AsnReader(certificate.RawData, AsnEncodingRules.DER);
        var certificateSequence = certificateReader.ReadSequence();
        var tbsCertificate = certificateSequence.ReadEncodedValue();
        var signatureAlgorithm = certificateSequence.ReadEncodedValue();
        var signature = certificateSequence.ReadBitString(out var unusedBitCount);
        certificateSequence.ThrowIfNotEmpty();
        certificateReader.ThrowIfNotEmpty();
        if (unusedBitCount != 0)
        {
            return false;
        }

        var tbsReader = new AsnReader(tbsCertificate, AsnEncodingRules.DER);
        var tbsSequence = tbsReader.ReadSequence();
        if (tbsSequence.PeekTag().TagClass == TagClass.ContextSpecific
         && tbsSequence.PeekTag().TagValue == 0)
        {
            tbsSequence.ReadEncodedValue();
        }

        tbsSequence.ReadIntegerBytes();
        var tbsSignatureAlgorithm = tbsSequence.ReadEncodedValue();
        if (!tbsSignatureAlgorithm.Span.SequenceEqual(signatureAlgorithm.Span))
        {
            return false;
        }

        var signatureAlgorithmOid = certificate.SignatureAlgorithm.Value;
        if (signatureAlgorithmOid is not (
            Oids.RsaPss or Oids.RsaPkcs1Sha256 or Oids.RsaPkcs1Sha384 or Oids.RsaPkcs1Sha512
         or "1.2.840.113549.1.1.5"
         or Oids.ECDsaWithSha256 or "1.2.840.10045.4.3.3" or "1.2.840.10045.4.3.4"
         or "1.2.840.10045.4.1"))
        {
            return false;
        }

        var hashAlgorithm = signatureAlgorithmOid.GetHashAlgorithmNameFromOid();
        if (issuer.GetRSAPublicKey() is { } rsa)
        {
            using (rsa)
            {
                var padding = signatureAlgorithmOid switch
                {
                    Oids.RsaPss => RSASignaturePadding.Pss,
                    Oids.RsaPkcs1Sha256 or Oids.RsaPkcs1Sha384 or Oids.RsaPkcs1Sha512
                     or "1.2.840.113549.1.1.5" => RSASignaturePadding.Pkcs1,
                    _ => null
                };
                return padding != null
                 && rsa.VerifyData(tbsCertificate.Span, signature, hashAlgorithm, padding);
            }
        }

        if (issuer.GetECDsaPublicKey() is { } ecdsa)
        {
            using (ecdsa)
            {
                return signatureAlgorithmOid is Oids.ECDsaWithSha256 or "1.2.840.10045.4.3.3"
                     or "1.2.840.10045.4.3.4" or "1.2.840.10045.4.1"
                 && ecdsa.VerifyData(
                        tbsCertificate.Span,
                        signature,
                        hashAlgorithm,
                        DSASignatureFormat.Rfc3279DerSequence);
            }
        }

        return false;
    }

    [LoggerMessage(LogLevel.Error, "Could not validate re-enrollment from {ReenrollingFrom}")]
    partial void LogCouldNotValidateReEnrollmentFromReEnrollingFrom(string reenrollingFrom);

    [LoggerMessage(LogLevel.Warning, "Re-enrollment refused: certificate {SerialNumber} is revoked")]
    partial void LogReEnrollmentFromRevokedCertificate(string serialNumber);
}
