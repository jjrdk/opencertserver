namespace OpenCertServer.Ca;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Utils;

public record CaConfiguration
{
    public X509Certificate2 RsaCertificate { get; }
    public X509Certificate2 EcdsaCertificate { get; }
    public TimeSpan CertificateValidity { get; }
    public string[] OcspUrls { get; }
    public string[] CaIssuersUrls { get; }

    public CaConfiguration(
        X509Certificate2 rsaCertificate,
        X509Certificate2 ecdsaCertificate,
        TimeSpan certificateValidity,
        string[] ocspUrls,
        string[] caIssuersUrls)
    {
        RsaCertificate = rsaCertificate;
        EcdsaCertificate = ecdsaCertificate;
        CertificateValidity = certificateValidity;
        OcspUrls = ocspUrls;
        CaIssuersUrls = caIssuersUrls;
    }
}

/// <summary>
/// Defines the certificate authority class.
/// </summary>
public sealed partial class CertificateAuthority : ICertificateAuthority, IDisposable
{
    private const string Header = "-----BEGIN CERTIFICATE REQUEST-----";
    private const string Footer = "-----END CERTIFICATE REQUEST-----";

    private const X509KeyUsageFlags UsageFlags = X509KeyUsageFlags.CrlSign
      | X509KeyUsageFlags.DataEncipherment
      | X509KeyUsageFlags.DecipherOnly
      | X509KeyUsageFlags.DigitalSignature
      | X509KeyUsageFlags.EncipherOnly
      | X509KeyUsageFlags.KeyAgreement
      | X509KeyUsageFlags.KeyCertSign
      | X509KeyUsageFlags.KeyEncipherment
      | X509KeyUsageFlags.NonRepudiation;

    private readonly CaConfiguration _config;
    private readonly ILogger<ICertificateAuthority> _logger;
    private readonly IStoreCertificates _certificateStore;
    private readonly Func<X509Chain, bool> _x509ChainValidation;
    private readonly IValidateCertificateRequests[] _validators;
    private readonly bool _standAlone;

    private CertificateAuthority(
        CaConfiguration config,
        IStoreCertificates certificateStore,
        Func<X509Chain, bool> x509ChainValidation,
        ILogger<CertificateAuthority> logger,
        Action<X509Certificate2, X509Certificate2>? certificateBackup = null,
        bool standAlone = true,
        params IValidateCertificateRequests[] validators)
        : this(
            config,
            certificateStore,
            x509ChainValidation,
            logger,
            certificateBackup,
            validators)
    {
        _standAlone = standAlone;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateAuthority"/> class.
    /// </summary>
    /// <param name="config">The <see cref="CaConfiguration"/>.</param>
    /// <param name="certificateStore"></param>
    /// <param name="x509ChainValidation"></param>
    /// <param name="logger"></param>
    /// <param name="certificateBackup"></param>
    /// <param name="validators"></param>
    /// <exception cref="ArgumentException"></exception>
    public CertificateAuthority(
        CaConfiguration config,
        IStoreCertificates certificateStore,
        Func<X509Chain, bool> x509ChainValidation,
        ILogger<CertificateAuthority> logger,
        Action<X509Certificate2, X509Certificate2>? certificateBackup = null,
        params IValidateCertificateRequests[] validators)
    {
        if (!config.RsaCertificate.HasPrivateKey)
        {
            throw new ArgumentException("RSA certificate must have private key", nameof(config));
        }

        if (!config.EcdsaCertificate.HasPrivateKey)
        {
            throw new ArgumentException("ECDSA certificate must have private key", nameof(config));
        }

        _config = config;
        _logger = logger;
        _certificateStore = certificateStore;
        _x509ChainValidation = x509ChainValidation;
        _validators = validators.Concat(
            [
                new OwnCertificateValidation(
                    [_config.RsaCertificate, _config.EcdsaCertificate],
                    _logger),
                new DistinguishedNameValidation()
            ])
            .ToArray();
        certificateBackup?.Invoke(_config.RsaCertificate, _config.EcdsaCertificate);
    }

    public static CertificateAuthority Create(
        X500DistinguishedName distinguishedName,
        Func<X509Certificate2, IStoreCertificates> certificateStore,
        TimeSpan certificateValidity,
        string[] ocspUrls,
        string[] caIssuersUrls,
        ILogger<CertificateAuthority> logger,
        Func<X509Chain, bool>? chainValidation = null,
        Action<X509Certificate2, X509Certificate2>? certificateBackup = null,
        params IValidateCertificateRequests[] validators)
    {
        var rsaCert = CreateSelfSignedRsaCert(
            distinguishedName,
            UsageFlags,
            certificateValidity);
        var ecdsaCert = CreateSelfSignedEcDsaCert(
            distinguishedName,
            UsageFlags,
            certificateValidity);
        var config = new CaConfiguration(
            rsaCert,
            ecdsaCert,
            certificateValidity,
            ocspUrls,
            caIssuersUrls);
        var ca = new CertificateAuthority(
            config,
            certificateStore(ecdsaCert),
            chainValidation ?? (_ => true),
            logger,
            certificateBackup,
            standAlone: true,
            validators);
        return ca;
    }

    public SignCertificateResponse SignCertificateRequest(
        CertificateRequest request,
        X509Certificate2? reenrollingFrom = null)
    {
        if (!_validators.Aggregate(true, (b, v) => b && v.Validate(request)))
        {
            LogCouldNotValidateRequest();
            return new SignCertificateResponse.Error("Could not validate request");
        }

        if (_logger.IsEnabled(LogLevel.Information))
        {
            LogCreatingCertificateForSubjectName(request.SubjectName.Name);
        }

        var toRemove = request.CertificateExtensions
            .Where(ext => ext is X509AuthorityInformationAccessExtension or X509AuthorityKeyIdentifierExtension)
            .ToArray();
        foreach (var ext in toRemove)
        {
            request.CertificateExtensions.Remove(ext);
        }
        request.CertificateExtensions.Add(
            new X509AuthorityInformationAccessExtension(_config.OcspUrls, _config.CaIssuersUrls));
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromCertificate(
                request.PublicKey.Oid.Value switch
                {
                    Oids.Rsa => _config.RsaCertificate,
                    Oids.EcPublicKey => _config.EcdsaCertificate,
                    _ => throw new InvalidOperationException($"Invalid Oid: {request.PublicKey.Oid.Value}")
                }, true, true));

        var cert = request.PublicKey.Oid.Value switch
        {
            Oids.Rsa => request.Create(
                _config.RsaCertificate,
                DateTimeOffset.UtcNow.Date,
                DateTimeOffset.UtcNow.Date.Add(_config.CertificateValidity),
                BitConverter.GetBytes(DateTimeOffset.UtcNow.Ticks)),
            Oids.EcPublicKey => request.Create(
                _config.EcdsaCertificate,
                DateTimeOffset.UtcNow.Date,
                DateTimeOffset.UtcNow.Date.Add(_config.CertificateValidity),
                BitConverter.GetBytes(DateTimeOffset.UtcNow.Ticks)),
            _ => null
        };

        if (cert == null)
        {
            return new SignCertificateResponse.Error("Unsupported key algorithm");
        }

        using var chain = new X509Chain();
        chain.ChainPolicy = new X509ChainPolicy
        {
            VerificationFlags = X509VerificationFlags.IgnoreEndRevocationUnknown
              | X509VerificationFlags.AllowUnknownCertificateAuthority
              | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown,
            RevocationFlag = X509RevocationFlag.ExcludeRoot
        };

        chain.ChainPolicy.ExtraStore.Add(_config.RsaCertificate);
        chain.ChainPolicy.ExtraStore.Add(_config.EcdsaCertificate);

        var chainBuilt = _standAlone || chain.Build(cert);

        if (chainBuilt || _x509ChainValidation(chain))
        {
            _certificateStore.AddCertificate(cert);
            return new SignCertificateResponse.Success(
                cert,
                [
                    request.PublicKey.Oid.Value switch
                    {
                        Oids.Rsa => _config.RsaCertificate,
                        Oids.EcPublicKey => _config.EcdsaCertificate,
                        _ => throw new InvalidOperationException($"Invalid Oid: {request.PublicKey.Oid.Value}")
                    }
                ]);
        }

        var errors = chain.ChainStatus.Select(chainStatus =>
                $"Certificate chain error: {chainStatus.Status} {chainStatus.StatusInformation}")
            .ToArray();
        LogErrors(string.Join(";", errors));

        return new SignCertificateResponse.Error(errors);
    }

    public SignCertificateResponse SignCertificateRequest(string request)
    {
        request = request.Replace(Header, "", StringComparison.OrdinalIgnoreCase)
            .Replace(Footer, "", StringComparison.OrdinalIgnoreCase)
            .Trim();

        var csr = Base64DecodeBytes(request);

        return SignCertificateRequest(csr);
    }

    private SignCertificateResponse SignCertificateRequest(byte[] request)
    {
        var csr = CertificateRequest.LoadSigningRequest(
            request,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
            RSASignaturePadding.Pss);

        return SignCertificateRequest(csr);
    }

    /// <inheritdoc />
    public X509Certificate2Collection GetRootCertificates()
    {
        return
        [
            X509Certificate2.CreateFromPem(_config.RsaCertificate.ExportCertificatePem()),
            X509Certificate2.CreateFromPem(_config.EcdsaCertificate.ExportCertificatePem())
        ];
    }

    public bool RevokeCertificate(string serialNumber, X509RevocationReason reason)
    {
        return _certificateStore.RemoveCertificate(serialNumber, reason);
    }

    public byte[] GetRevocationList()
    {
        return _certificateStore.GetRevocationList();
    }

    private static X509Certificate2 CreateSelfSignedRsaCert(
        X500DistinguishedName distinguishedName,
        X509KeyUsageFlags usageFlags,
        TimeSpan certificateValidity)
    {
        using var parent = RSA.Create(3072);
        var parentReq = new CertificateRequest(
            distinguishedName,
            parent,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        return SelfSignCert(usageFlags, certificateValidity, parentReq);
    }

    private static X509Certificate2 CreateSelfSignedEcDsaCert(
        X500DistinguishedName distinguishedName,
        X509KeyUsageFlags usageFlags,
        TimeSpan certificateValidity)
    {
        using var parent = ECDsa.Create();
        var parentReq = new CertificateRequest(
            distinguishedName,
            parent,
            HashAlgorithmName.SHA256);

        return SelfSignCert(usageFlags, certificateValidity, parentReq);
    }

    private static X509Certificate2 SelfSignCert(
        X509KeyUsageFlags usageFlags,
        TimeSpan certificateValidity,
        CertificateRequest parentReq)
    {
        parentReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        parentReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(parentReq.PublicKey, false));
        parentReq.CertificateExtensions.Add(new X509KeyUsageExtension(usageFlags, true));

        var parentCert = parentReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.Date,
            DateTimeOffset.UtcNow.Date.Add(certificateValidity));

        return parentCert;
    }

    public void Dispose()
    {
        _config.RsaCertificate.Dispose();
        _config.EcdsaCertificate.Dispose();
    }

    /// <summary>
    /// Base64 decode.
    /// </summary>
    /// <param name="base64EncodedData">The base64 encoded data.</param>
    /// <returns></returns>
    private static byte[] Base64DecodeBytes(string base64EncodedData)
    {
        var s = base64EncodedData
            .Replace(" ", "+")
            .Replace('-', '+')
            .Replace('_', '/')
            .Replace("\n", "")
            .Replace("\r", "")
            .Trim();
        switch (s.Length % 4)
        {
            case 0:
                return Convert.FromBase64String(s);
            case 2:
                s += "==";
                goto case 0;
            case 3:
                s += "=";
                goto case 0;
            default:
                throw new InvalidOperationException("Illegal base64url string!");
        }
    }

    private sealed partial class OwnCertificateValidation(X509Certificate2Collection serverCertificates, ILogger logger)
        : IValidateCertificateRequests
    {
        public bool Validate(CertificateRequest request, X509Certificate2? reenrollingFrom = null)
        {
            var result = reenrollingFrom == null
             || serverCertificates
                    .Aggregate(false, (b, cert) => b || reenrollingFrom.IssuerName.Name == cert.SubjectName.Name);
            if (!result)
            {
                LogCouldNotValidateReEnrollmentFromReEnrollingFrom(reenrollingFrom!.IssuerName.Name);
            }

            return result;
        }

        [LoggerMessage(LogLevel.Error, "Could not validate re-enrollment from {ReenrollingFrom}")]
        partial void LogCouldNotValidateReEnrollmentFromReEnrollingFrom(string reenrollingFrom);
    }

    private sealed class DistinguishedNameValidation : IValidateCertificateRequests
    {
        public bool Validate(CertificateRequest request, X509Certificate2? reenrollingFrom = null)
        {
            return request.SubjectName.Format(true)
                .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                .Any(x => x.StartsWith("CN="));
        }
    }

    [LoggerMessage(LogLevel.Error, "Could not validate request")]
    partial void LogCouldNotValidateRequest();

    [LoggerMessage(LogLevel.Information, "Creating certificate for {SubjectName}")]
    partial void LogCreatingCertificateForSubjectName(string subjectName);

    [LoggerMessage(LogLevel.Error, "{Errors}")]
    partial void LogErrors(string errors);
}
