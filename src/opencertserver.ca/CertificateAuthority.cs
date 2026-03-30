namespace OpenCertServer.Ca;

using System;
using System.Linq;
using System.Numerics;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Utils.Ca;
using Utils;

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
    private readonly IValidateX509Chains _x509ChainValidation;
    private readonly IValidateCertificateRequests[] _validators;

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateAuthority"/> class.
    /// </summary>
    /// <param name="config">The <see cref="CaConfiguration"/>.</param>
    /// <param name="certificateStore"></param>
    /// <param name="x509ChainValidation"></param>
    /// <param name="logger"></param>
    /// <param name="validators"></param>
    /// <exception cref="ArgumentException"></exception>
    public CertificateAuthority(
        CaConfiguration config,
        IStoreCertificates certificateStore,
        IValidateX509Chains x509ChainValidation,
        ILogger<CertificateAuthority> logger,
        params IValidateCertificateRequests[] validators)
    {
        _config = config;
        _logger = logger;
        _certificateStore = certificateStore;
        _x509ChainValidation = x509ChainValidation;
        _validators =
        [
            ..validators,
            new OwnCertificateValidation(_config.Profiles, _logger),
            new DistinguishedNameValidation(_logger)
        ];
    }

    public static CaProfile CreateSelfSignedRsa(
        string profileName,
        X500DistinguishedName distinguishedName,
        TimeSpan certificateValidity,
        BigInteger? crlNumber = null)
    {
        var (key, cert) = CreateSelfSignedRsaCert(
            distinguishedName,
            UsageFlags,
            certificateValidity);
        return new CaProfile
        {
            Name = profileName,
            PrivateKey = key,
            CertificateChain = [cert],
            CertificateValidity = certificateValidity,
            CrlNumber = crlNumber ?? BigInteger.Zero
        };
    }

    public static CaProfile CreateSelfSignedEcdsa(
        string profileName,
        X500DistinguishedName distinguishedName,
        TimeSpan certificateValidity,
        BigInteger? crlNumber = null)
    {
        var (key, cert) = CreateSelfSignedEcDsaCert(
            distinguishedName,
            UsageFlags,
            certificateValidity);
        return new CaProfile
        {
            Name = profileName,
            PrivateKey = key,
            CertificateChain = [cert],
            CertificateValidity = certificateValidity,
            CrlNumber = crlNumber ?? BigInteger.Zero
        };
    }

    /// <inheritdoc/>
    public async Task<SignCertificateResponse> SignCertificateRequest(
        CertificateRequest request,
        string? profileName = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        CancellationToken cancellationToken = default)
    {
        var profile = await _config.Profiles.GetProfile(profileName, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (request.PublicKey.Oid.Value != profile.CertificateChain[0].PublicKey.Oid.Value)
        {
            return new SignCertificateResponse.Error("Public key algorithm does not match CA certificate");
        }

        var validationResults = await Task.WhenAll(_validators.Select(v =>
            v.Validate(request, profileName, requestor, reenrollingFrom, cancellationToken)));
        var validationResult = validationResults.Where(r => r != null).ToArray();
        if (validationResult.Length > 0)
        {
            LogCouldNotValidateRequest();
            return new SignCertificateResponse.Error(string.Join("\n", validationResult));
        }

        LogCreatingCertificateForSubjectName(request.SubjectName.Name);

        var toRemove = request.CertificateExtensions
            .Where(ext => ext is X509AuthorityInformationAccessExtension
             or X509AuthorityKeyIdentifierExtension)
            .Concat(request.CertificateExtensions.Where(ext => ext.Oid?.Value == Oids.CrlDistributionPoints))
            .ToArray();
        foreach (var ext in toRemove)
        {
            request.CertificateExtensions.Remove(ext);
        }

        if (_config.CrlUrls.Length > 0)
        {
            request.CertificateExtensions.Add(
                CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(_config.CrlUrls));
        }

        if (_config.OcspUrls.Length > 0 || _config.CaIssuersUrls.Length > 0)
        {
            request.CertificateExtensions.Add(
                new X509AuthorityInformationAccessExtension(_config.OcspUrls, _config.CaIssuersUrls));
        }

        request.CertificateExtensions.Add(
            X509AuthorityKeyIdentifierExtension.CreateFromSubjectKeyIdentifier(request.PublicKey
                .ExportSubjectPublicKeyInfo()));

        var profilePrivateKey = profile.PrivateKey;
        var x509SignatureGenerator = profilePrivateKey switch
        {
            RSA rsa => X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pss),
            ECDsa ecdsa => X509SignatureGenerator.CreateForECDsa(ecdsa),
            _ => throw new NotSupportedException()
        };
        var cert = request.Create(
            profile.CertificateChain[0].SubjectName,
            x509SignatureGenerator,
            DateTimeOffset.UtcNow.Date,
            DateTimeOffset.UtcNow.Date.Add(profile.CertificateValidity),
            BitConverter.GetBytes(DateTimeOffset.UtcNow.Ticks));

        using var chain = new X509Chain();
        chain.ChainPolicy = new X509ChainPolicy
        {
            VerificationFlags = X509VerificationFlags.IgnoreEndRevocationUnknown
              | X509VerificationFlags.AllowUnknownCertificateAuthority
              | X509VerificationFlags.IgnoreCertificateAuthorityRevocationUnknown,
            RevocationFlag = X509RevocationFlag.ExcludeRoot
        };

        chain.ChainPolicy.ExtraStore.AddRange(profile.CertificateChain);

        var chainBuilt = chain.Build(cert);

        if (chainBuilt || _x509ChainValidation.Validate(chain))
        {
            await _certificateStore.AddCertificate(cert, cancellationToken);
            if (reenrollingFrom != null)
            {
                await _certificateStore.RemoveCertificate(reenrollingFrom.SerialNumber, X509RevocationReason.Superseded,
                    cancellationToken);
            }

            return new SignCertificateResponse.Success(
                cert,
                profile.CertificateChain);
        }

        var errors = chain.ChainStatus.Select(chainStatus =>
                $"Certificate chain error: {chainStatus.Status} {chainStatus.StatusInformation}")
            .ToArray();
        LogErrors(string.Join(";", errors));

        return new SignCertificateResponse.Error(errors);
    }

    /// <inheritdoc/>
    public Task<SignCertificateResponse> SignCertificateRequestPem(
        string request,
        string? profileName = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null,
        CancellationToken cancellationToken = default)
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

        return SignCertificateRequest(csr, profileName, requestor, reenrollingFrom);
    }

    private Task<SignCertificateResponse> SignCertificateRequest(
        byte[] request,
        string? profileName = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null)
    {
        var csr = CertificateRequest.LoadSigningRequest(
            request,
            HashAlgorithmName.SHA256,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
            RSASignaturePadding.Pss);

        return SignCertificateRequest(csr, profileName, requestor, reenrollingFrom);
    }

    /// <inheritdoc />
    public async Task<X509Certificate2Collection> GetRootCertificates(
        string? profileName = null,
        CancellationToken cancellationToken = default)
    {
        var profile = await _config.Profiles.GetProfile(profileName, cancellationToken);
        return profile.CertificateChain;
    }

    /// <inheritdoc/>
    public Task<bool> RevokeCertificate(string serialNumber, X509RevocationReason reason)
    {
        return _certificateStore.RemoveCertificate(serialNumber, reason);
    }

    /// <inheritdoc/>
    public async Task<byte[]> GetRevocationList(
        string? profileName = null,
        CancellationToken cancellationToken = default)
    {
        var profile = await _config.Profiles.GetProfile(profileName, cancellationToken);
        var list = _certificateStore.GetRevocationList(cancellationToken: cancellationToken);
        var builder = new CertificateRevocationListBuilder();
        await foreach (var revoked in list.ConfigureAwait(false))
        {
            builder.AddEntry(
                Encoding.UTF8.GetBytes(revoked.SerialNumber),
                revoked.RevocationDate,
                revoked.RevocationReason);
        }

        var crl = builder.Build(
            profile.CertificateChain[0],
            profile.CrlNumber + 1,
            DateTimeOffset.UtcNow.AddDays(7),
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss, thisUpdate: DateTimeOffset.UtcNow);
        return crl;
    }

    private static (RSA, X509Certificate2) CreateSelfSignedRsaCert(
        X500DistinguishedName distinguishedName,
        X509KeyUsageFlags usageFlags,
        TimeSpan certificateValidity)
    {
        var parent = RSA.Create(3072);
        var parentReq = new CertificateRequest(
            distinguishedName,
            parent,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        return (parent, SelfSignCert(usageFlags, certificateValidity, parentReq));
    }

    private static (ECDsa, X509Certificate2) CreateSelfSignedEcDsaCert(
        X500DistinguishedName distinguishedName,
        X509KeyUsageFlags usageFlags,
        TimeSpan certificateValidity)
    {
        var parent = ECDsa.Create();
        var parentReq = new CertificateRequest(
            distinguishedName,
            parent,
            HashAlgorithmName.SHA256);

        return (parent, SelfSignCert(usageFlags, certificateValidity, parentReq));
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

    /// <inheritdoc/>
    public void Dispose()
    {
        _config.Dispose();
    }

    private sealed partial class OwnCertificateValidation(IStoreCaProfiles caProfiles, ILogger logger)
        : IValidateCertificateRequests
    {
        public async Task<string?> Validate(
            CertificateRequest request,
            string? profile = null,
            ClaimsIdentity? requestor = null,
            X509Certificate2? reenrollingFrom = null,
            CancellationToken cancellationToken = default)
        {
            var caProfile = await caProfiles.GetProfile(profile, cancellationToken);
            var result = reenrollingFrom == null
             || caProfile.CertificateChain
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

        public Task<string?> Validate(
            CertificateRequest request,
            string? profile,
            ClaimsIdentity? requestor,
            X509Certificate2? reenrollingFrom = null,
            CancellationToken cancellationToken = default)
        {
            if (request.SubjectName.Format(true)
                .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                .Any(x => x.StartsWith("CN=")))
                return Task.FromResult<string?>(null);

            LogDistinguishedNameNameDoesNotContainACommonNameCnAttribute(request.SubjectName.Format(false));
            return Task.FromResult<string?>("Subject name must contain a Common Name (CN) attribute");
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
