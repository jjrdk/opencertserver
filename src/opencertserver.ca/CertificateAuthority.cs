namespace OpenCertServer.Ca;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Utils;

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

    private readonly ILogger<ICertificateAuthority> _logger;
    private readonly X509Certificate2 _rsaCertificate;
    private readonly X509Certificate2 _ecdsaCertificate;
    private readonly IStoreCertificates _certificateStore;
    private readonly TimeSpan _certificateValidity;
    private readonly Func<X509Chain, bool> _x509ChainValidation;
    private readonly IValidateCertificateRequests[] _validators;
    private readonly bool _standAlone;

    private CertificateAuthority(
        X509Certificate2 rsaCertificate,
        X509Certificate2 ecdsaCertificate,
        IStoreCertificates certificateStore,
        TimeSpan certificateValidity,
        Func<X509Chain, bool> x509ChainValidation,
        ILogger<CertificateAuthority> logger,
        Action<X509Certificate2, X509Certificate2>? certificateBackup = null,
        bool standAlone = true,
        params IValidateCertificateRequests[] validators)
        : this(
            rsaCertificate,
            ecdsaCertificate,
            certificateStore,
            certificateValidity,
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
    /// <param name="rsaCertificate"></param>
    /// <param name="ecdsaCertificate"></param>
    /// <param name="certificateStore"></param>
    /// <param name="certificateValidity"></param>
    /// <param name="x509ChainValidation"></param>
    /// <param name="logger"></param>
    /// <param name="certificateBackup"></param>
    /// <param name="validators"></param>
    /// <exception cref="ArgumentException"></exception>
    public CertificateAuthority(
        X509Certificate2 rsaCertificate,
        X509Certificate2 ecdsaCertificate,
        IStoreCertificates certificateStore,
        TimeSpan certificateValidity,
        Func<X509Chain, bool> x509ChainValidation,
        ILogger<CertificateAuthority> logger,
        Action<X509Certificate2, X509Certificate2>? certificateBackup = null,
        params IValidateCertificateRequests[] validators)
    {
        if (!rsaCertificate.HasPrivateKey)
        {
            throw new ArgumentException("RSA certificate must have private key", nameof(rsaCertificate));
        }

        if (!ecdsaCertificate.HasPrivateKey)
        {
            throw new ArgumentException("ECDSA certificate must have private key", nameof(ecdsaCertificate));
        }

        _logger = logger;
        _rsaCertificate = rsaCertificate;
        _ecdsaCertificate = ecdsaCertificate;
        _certificateStore = certificateStore;
        _certificateValidity = certificateValidity;
        _x509ChainValidation = x509ChainValidation;
        _validators = validators.Concat(
            [
                new OwnCertificateValidation(
                    [_rsaCertificate, _ecdsaCertificate],
                    _logger),
                new DistinguishedNameValidation()
            ])
            .ToArray();
        certificateBackup?.Invoke(_rsaCertificate, _ecdsaCertificate);
    }

    public static CertificateAuthority Create(
        X500DistinguishedName distinguishedName,
        Func<X509Certificate2, IStoreCertificates> certificateStore,
        TimeSpan certificateValidity,
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
        var ca = new CertificateAuthority(
            rsaCert,
            ecdsaCert,
            certificateStore(ecdsaCert),
            certificateValidity,
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
            LogCreatingCertificateForSubjectname(request.SubjectName.Name);
        }

        var cert = request.PublicKey.Oid.Value switch
        {
            CertificateConstants.RsaOid => request.Create(
                _rsaCertificate,
                DateTimeOffset.UtcNow.Date,
                DateTimeOffset.UtcNow.Date.Add(_certificateValidity),
                BitConverter.GetBytes(DateTimeOffset.UtcNow.Ticks)),
            CertificateConstants.EcdsaOid => request.Create(
                _ecdsaCertificate,
                DateTimeOffset.UtcNow.Date,
                DateTimeOffset.UtcNow.Date.Add(_certificateValidity),
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

        chain.ChainPolicy.ExtraStore.Add(_rsaCertificate);
        chain.ChainPolicy.ExtraStore.Add(_ecdsaCertificate);

        var chainBuilt = _standAlone || chain.Build(cert);

        if (chainBuilt || _x509ChainValidation(chain))
        {
            _certificateStore.AddCertificate(cert);
            return new SignCertificateResponse.Success(
                cert,
                [
                    request.PublicKey.Oid.Value switch
                    {
                        "1.2.840.113549.1.1.1" => _rsaCertificate,
                        "1.2.840.10045.2.1" => _ecdsaCertificate,
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
            X509Certificate2.CreateFromPem(_rsaCertificate.ExportCertificatePem()),
            X509Certificate2.CreateFromPem(_ecdsaCertificate.ExportCertificatePem())
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
        using var parent = RSA.Create(4096);
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
        _rsaCertificate.Dispose();
        _ecdsaCertificate.Dispose();
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

    private sealed partial class OwnCertificateValidation : IValidateCertificateRequests
    {
        private readonly X509Certificate2Collection _serverCertificates;
        private readonly ILogger _logger;

        public OwnCertificateValidation(X509Certificate2Collection serverCertificates, ILogger logger)
        {
            _serverCertificates = serverCertificates;
            _logger = logger;
        }

        public bool Validate(CertificateRequest request, X509Certificate2? reenrollingFrom = null)
        {
            var result = reenrollingFrom == null
             || _serverCertificates
                    .Aggregate(false, (b, cert) => b || reenrollingFrom.IssuerName.Name == cert.SubjectName.Name);
            if (!result)
            {
                LogCouldNotValidateReEnrollmentFromReEnrollingfrom(reenrollingFrom!.IssuerName.Name);
            }

            return result;
        }

        [LoggerMessage(LogLevel.Error, "Could not validate re-enrollment from {ReenrollingFrom}")]
        partial void LogCouldNotValidateReEnrollmentFromReEnrollingfrom(string reenrollingFrom);
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
    partial void LogCreatingCertificateForSubjectname(string subjectName);

    [LoggerMessage(LogLevel.Error, "{Errors}")]
    partial void LogErrors(string errors);
}
