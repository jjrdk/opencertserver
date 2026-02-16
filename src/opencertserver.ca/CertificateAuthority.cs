using System.Numerics;
using System.Text;
using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Ca;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Utils;

public record CaConfiguration
{
    private readonly byte[] _rsaBytes;
    private readonly byte[] _ecdsaBytes;

    public CaConfiguration(
        X509Certificate2 rsaCertificate,
        X509Certificate2 ecdsaCertificate,
        BigInteger crlNumber,
        TimeSpan certificateValidity,
        string[] ocspUrls,
        string[] caIssuersUrls)
    {
        _rsaBytes = rsaCertificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, null);
        _ecdsaBytes = ecdsaCertificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pbes2Aes256Sha256, null);
        CrlNumber = crlNumber;
        CertificateValidity = certificateValidity;
        OcspUrls = ocspUrls;
        CaIssuersUrls = caIssuersUrls;
    }

    public X509Certificate2 RsaCertificate
    {
        get
        {
            return X509CertificateLoader.LoadPkcs12(_rsaBytes, null,
                loaderLimits: Pkcs12LoaderLimits.Defaults);
        }
    }

    public X509Certificate2 EcdsaCertificate
    {
        get
        {
            return X509CertificateLoader.LoadPkcs12(_ecdsaBytes, null,
                loaderLimits: Pkcs12LoaderLimits.Defaults);
        }
    }

    public BigInteger CrlNumber { get; }
    public TimeSpan CertificateValidity { get; }
    public string[] OcspUrls { get; }
    public string[] CaIssuersUrls { get; }

    internal X509Certificate2 GetExportableRsaCertificate()
    {
        return X509CertificateLoader.LoadPkcs12(_rsaBytes, null,
            keyStorageFlags: X509KeyStorageFlags.Exportable,
            loaderLimits: Pkcs12LoaderLimits.Defaults);
    }

    internal X509Certificate2 GetExportableEcdsaCertificate()
    {
        return X509CertificateLoader.LoadPkcs12(_ecdsaBytes, null,
            keyStorageFlags: X509KeyStorageFlags.Exportable,
            loaderLimits: Pkcs12LoaderLimits.Defaults);
    }
}

/// <summary>
/// Defines the certificate authority class.
/// </summary>
public sealed partial class CertificateAuthority : ICertificateAuthority, IDisposable
{
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
        _validators =
        [
            ..validators,
            new OwnCertificateValidation([_config.RsaCertificate, _config.EcdsaCertificate], _logger),
            new DistinguishedNameValidation(_logger)
        ];

        certificateBackup?.Invoke(_config.GetExportableRsaCertificate(), _config.GetExportableEcdsaCertificate());
    }

    public static CertificateAuthority CreateSelfSigned(
        X500DistinguishedName distinguishedName,
        IStoreCertificates certificateStore,
        TimeSpan certificateValidity,
        string[] ocspUrls,
        string[] caIssuersUrls,
        ILogger<CertificateAuthority> logger,
        BigInteger? crlNumber = null,
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
            crlNumber ?? BigInteger.Zero,
            certificateValidity,
            ocspUrls,
            caIssuersUrls);
        var ca = new CertificateAuthority(
            config,
            certificateStore,
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
        var validationResult = _validators.Aggregate(new List<string>(), (b, v) =>
        {
            var reason = v.Validate(request);
            if (reason != null)
            {
                b.Add(reason);
            }

            return b;
        });
        if (validationResult.Count > 0)
        {
            LogCouldNotValidateRequest();
            return new SignCertificateResponse.Error(string.Join("\n", validationResult));
        }

        LogCreatingCertificateForSubjectName(request.SubjectName.Name);

        var toRemove = request.CertificateExtensions
            .Where(ext => ext is X509AuthorityInformationAccessExtension or X509AuthorityKeyIdentifierExtension)
            .ToArray();
        foreach (var ext in toRemove)
        {
            request.CertificateExtensions.Remove(ext);
        }

        new X509EnhancedKeyUsageExtension(new OidCollection{Oids.ServerAuthenticationPurpose.InitializeOid()}, true);
        request.CertificateExtensions.Add(
            new X509AuthorityInformationAccessExtension(_config.OcspUrls, _config.CaIssuersUrls));
        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(request.PublicKey
                .ExportSubjectPublicKeyInfo()));

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
            if (reenrollingFrom != null)
            {
                _certificateStore.RemoveCertificate(reenrollingFrom.SerialNumber, X509RevocationReason.Superseded);
            }

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

    public SignCertificateResponse SignCertificateRequestPem(string request)
    {
        var hasPem = PemEncoding.TryFind(request, out var fields);
        byte[] csr;
        if (!hasPem)
        {
            csr = request.Base64DecodeBytes();
        }
        else
        {
            var r = request.AsSpan(fields.Base64Data);
            csr = Convert.FromBase64CharArray(r.ToArray(), 0, r.Length);
        }

        return SignCertificateRequest(csr);
    }

    private SignCertificateResponse SignCertificateRequest(byte[] request, X509Certificate2? reenrollingFrom = null)
    {
        var csr = CertificateRequest.LoadSigningRequest(
            request,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
            RSASignaturePadding.Pss);

        return SignCertificateRequest(csr, reenrollingFrom);
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

    public Task<bool> RevokeCertificate(string serialNumber, X509RevocationReason reason)
    {
        return _certificateStore.RemoveCertificate(serialNumber, reason);
    }

    public async Task<byte[]> GetRevocationList()
    {
        var list = _certificateStore.GetRevocationList();
        var builder = new CertificateRevocationListBuilder();
        await foreach (var revoked in list)
        {
            builder.AddEntry(
                Encoding.UTF8.GetBytes(revoked.SerialNumber),
                revoked.RevocationDate,
                revoked.RevocationReason);
        }

        var crl = builder.Build(
            _config.EcdsaCertificate,
            _config.CrlNumber + 1,
            DateTimeOffset.UtcNow.AddDays(7),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss, thisUpdate: DateTimeOffset.UtcNow);
        return crl;
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

    private sealed partial class OwnCertificateValidation(X509Certificate2Collection serverCertificates, ILogger logger)
        : IValidateCertificateRequests
    {
        public string? Validate(CertificateRequest request, X509Certificate2? reenrollingFrom = null)
        {
            var result = reenrollingFrom == null
             || serverCertificates
                    .Aggregate(false, (b, cert) => b || reenrollingFrom.IssuerName.Name == cert.SubjectName.Name);
            if (result)
            {
                return null;
            }

            LogCouldNotValidateReEnrollmentFromReEnrollingFrom(reenrollingFrom!.IssuerName.Name);
            return "Re-enrollment certificate is not issued by this CA";
        }

        [LoggerMessage(LogLevel.Error, "Could not validate re-enrollment from {ReenrollingFrom}")]
        partial void LogCouldNotValidateReEnrollmentFromReEnrollingFrom(string reenrollingFrom);
    }

    private sealed partial class DistinguishedNameValidation : IValidateCertificateRequests
    {
        private readonly ILogger _logger;

        public DistinguishedNameValidation(ILogger logger)
        {
            _logger = logger;
        }

        public string? Validate(CertificateRequest request, X509Certificate2? reenrollingFrom = null)
        {
            if (request.SubjectName.Format(true)
                .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                .Any(x => x.StartsWith("CN=")))
                return null;

            LogDistinguishedNameNameDoesNotContainACommonNameCnAttribute(request.SubjectName.Format(false));
            return "Subject name must contain a Common Name (CN) attribute";
        }

        [LoggerMessage(LogLevel.Error, "{DistinguishedName} name does not contain a Common Name (CN) attribute")]
        partial void LogDistinguishedNameNameDoesNotContainACommonNameCnAttribute(string distinguishedName);
    }

    [LoggerMessage(LogLevel.Error, "Could not validate request")]
    partial void LogCouldNotValidateRequest();

    [LoggerMessage(LogLevel.Information, "Creating certificate for {SubjectName}")]
    partial void LogCreatingCertificateForSubjectName(string subjectName);

    [LoggerMessage(LogLevel.Error, "{Errors}")]
    partial void LogErrors(string errors);
}
