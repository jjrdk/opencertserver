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

        // The issuer signature proves CA ownership, not profile membership: profiles may share a key.
        var issuingProfile = await _certificateStore
            .GetIssuingProfile(reenrollingFrom.Thumbprint, cancellationToken).ConfigureAwait(false);
        if (issuingProfile == null
         || !string.Equals(issuingProfile, caProfile.Name, StringComparison.Ordinal))
        {
            LogReEnrollmentProfileMismatch(reenrollingFrom.Thumbprint, issuingProfile, caProfile.Name);
            return "Re-enrollment certificate issuing profile is unknown or does not match the requested profile";
        }

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

        var isRsaPss = signatureAlgorithmOid == Oids.RsaPss;
        HashAlgorithmName hashAlgorithm;
        try
        {
            hashAlgorithm = isRsaPss
                ? GetRsaPssHashAlgorithm(signatureAlgorithm)
                : signatureAlgorithmOid.GetHashAlgorithmNameFromOid();
        }
        catch (Exception exception) when (exception is AsnContentException or CryptographicException)
        {
            return false;
        }

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

    private static HashAlgorithmName GetRsaPssHashAlgorithm(ReadOnlyMemory<byte> encodedAlgorithm)
    {
        var reader = new AsnReader(encodedAlgorithm, AsnEncodingRules.DER);
        var algorithm = reader.ReadSequence();
        if (algorithm.ReadObjectIdentifier() != Oids.RsaPss)
        {
            throw new CryptographicException("Invalid RSASSA-PSS algorithm identifier.");
        }

        var hashAlgorithm = HashAlgorithmName.SHA1;
        var maskHashAlgorithm = HashAlgorithmName.SHA1;
        var saltLength = 20;
        var trailerField = 1;
        if (algorithm.HasData)
        {
            var parameters = algorithm.ReadSequence();
            var previousTagValue = -1;
            while (parameters.HasData)
            {
                var tag = parameters.PeekTag();
                if (tag.TagClass != TagClass.ContextSpecific || tag.TagValue <= previousTagValue)
                {
                    throw new CryptographicException("Invalid RSASSA-PSS parameters.");
                }

                previousTagValue = tag.TagValue;
                switch (tag.TagValue)
                {
                    case 0:
                        hashAlgorithm = ReadHashAlgorithm(parameters.ReadSequence(
                            new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)));
                        break;
                    case 1:
                        maskHashAlgorithm = ReadMaskGenerationHashAlgorithm(parameters.ReadSequence(
                            new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: true)));
                        break;
                    case 2:
                        saltLength = ReadExplicitInteger(parameters, 2);
                        break;
                    case 3:
                        trailerField = ReadExplicitInteger(parameters, 3);
                        break;
                    default:
                        throw new CryptographicException("Unsupported RSASSA-PSS parameter.");
                }
            }
        }

        algorithm.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();
        var expectedSaltLength = hashAlgorithm == HashAlgorithmName.SHA1 ? 20
            : hashAlgorithm == HashAlgorithmName.SHA256 ? 32
            : hashAlgorithm == HashAlgorithmName.SHA384 ? 48
            : hashAlgorithm == HashAlgorithmName.SHA512 ? 64
            : -1;
        if (maskHashAlgorithm != hashAlgorithm || saltLength != expectedSaltLength || trailerField != 1)
        {
            throw new CryptographicException("Unsupported RSASSA-PSS parameters.");
        }

        return hashAlgorithm;
    }

    private static HashAlgorithmName ReadHashAlgorithm(AsnReader algorithm)
    {
        var hashAlgorithm = ReadHashAlgorithmIdentifier(algorithm);
        algorithm.ThrowIfNotEmpty();
        return hashAlgorithm;
    }

    private static HashAlgorithmName ReadMaskGenerationHashAlgorithm(AsnReader algorithm)
    {
        var maskGenerationAlgorithm = algorithm.ReadSequence();
        if (maskGenerationAlgorithm.ReadObjectIdentifier() != "1.2.840.113549.1.1.8"
         || !maskGenerationAlgorithm.HasData)
        {
            throw new CryptographicException("Unsupported RSASSA-PSS mask generation algorithm.");
        }

        var hashAlgorithmReader = new AsnReader(maskGenerationAlgorithm.ReadEncodedValue(), AsnEncodingRules.DER);
        var hashAlgorithm = ReadHashAlgorithmIdentifier(hashAlgorithmReader);
        hashAlgorithmReader.ThrowIfNotEmpty();
        maskGenerationAlgorithm.ThrowIfNotEmpty();
        algorithm.ThrowIfNotEmpty();
        return hashAlgorithm;
    }

    private static HashAlgorithmName ReadHashAlgorithmIdentifier(AsnReader reader)
    {
        var algorithm = reader.ReadSequence();
        var hashAlgorithm = algorithm.ReadObjectIdentifier() switch
        {
            "1.3.14.3.2.26" => HashAlgorithmName.SHA1,
            "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256,
            "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
            "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
            _ => throw new CryptographicException("Unsupported RSASSA-PSS hash algorithm.")
        };
        if (algorithm.HasData)
        {
            algorithm.ReadNull();
        }

        algorithm.ThrowIfNotEmpty();
        return hashAlgorithm;
    }

    private static int ReadExplicitInteger(AsnReader reader, int tagValue)
    {
        var explicitValue = reader.ReadSequence(
            new Asn1Tag(TagClass.ContextSpecific, tagValue, isConstructed: true));
        var value = explicitValue.ReadInteger();
        explicitValue.ThrowIfNotEmpty();
        if (value < 0 || value > int.MaxValue)
        {
            throw new CryptographicException("Invalid RSASSA-PSS integer parameter.");
        }

        return (int)value;
    }

    [LoggerMessage(LogLevel.Error, "Could not validate re-enrollment from {ReenrollingFrom}")]
    partial void LogCouldNotValidateReEnrollmentFromReEnrollingFrom(string reenrollingFrom);

    [LoggerMessage(LogLevel.Warning, "Re-enrollment refused: certificate {SerialNumber} is revoked")]
    partial void LogReEnrollmentFromRevokedCertificate(string serialNumber);

    [LoggerMessage(LogLevel.Warning,
        "Re-enrollment refused: certificate {Thumbprint} issuing profile {IssuingProfile} does not match requested profile {RequestedProfile}, or is unknown")]
    partial void LogReEnrollmentProfileMismatch(string thumbprint, string? issuingProfile, string requestedProfile);
}
