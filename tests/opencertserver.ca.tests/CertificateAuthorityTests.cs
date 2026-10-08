namespace OpenCertServer.Ca.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Ca.Utils.Ca;
using Utils;
using Xunit;

public sealed class CertificateAuthorityTests : IDisposable
{
    private readonly ICertificateAuthority _authority;

    public CertificateAuthorityTests()
    {
        var ecdsa = ECDsa.Create();
        var ecdsaReq = new CertificateRequest("CN=Test Server", ecdsa, HashAlgorithmName.SHA256);
        ecdsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
        ecdsaReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(new PublicKey(ecdsa),
            X509SubjectKeyIdentifierHashAlgorithm.Sha256, false));
        var ecdsaCert = ecdsaReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.Date,
            DateTimeOffset.UtcNow.Date.AddYears(1));
        var rsa = RSA.Create(4096);
        var rsaReq = new CertificateRequest(
            "CN=Test Server",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        rsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
        rsaReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(new PublicKey(rsa),
            X509SubjectKeyIdentifierHashAlgorithm.Sha256, false));
        var rsaCert = rsaReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.Date,
            DateTimeOffset.UtcNow.Date.AddYears(1));
        var caProfileSet = new CaProfileSet(
            "rsa",
            new CaProfile
            {
                CertificateChain = [X509Certificate2.CreateFromPem(rsaCert.ExportCertificatePem())],
                Name = "rsa",
                CertificateValidity = TimeSpan.FromDays(90),
                PrivateKey = rsa
            },
            new CaProfile
            {
                CertificateChain = [X509Certificate2.CreateFromPem(ecdsaCert.ExportCertificatePem())],
                Name = "ecdsa",
                CertificateValidity = TimeSpan.FromDays(90),
                PrivateKey = ecdsa
            }
        );
        _authority = new CertificateAuthority(
            new CaConfiguration(
                caProfileSet,
                ["test"],
                [],
                []),
            new InMemoryCertificateStore(),
            new ValidateAll(),
            new RandomNumberCertificateIdGenerator(),
            new NullLogger<CertificateAuthority>(),
            new CaExtensionValidation(caProfileSet, new NullLogger<CaExtensionValidation>()),
            new DistinguishedNameValidation(new NullLogger<DistinguishedNameValidation>()),
            new OwnCertificateValidation(caProfileSet, new NullLogger<OwnCertificateValidation>()),
            new NoCertSignExtension()
        );
    }

    [Fact]
    public async Task CanSerializeCertificateRequest()
    {
        using var rsa = RSA.Create(2048);

        var req = CreateCertificateRequest(rsa);
        var bytes = req.CreateSigningRequest();
        var cert =
            await _authority.SignCertificateRequestPem(
                PemEncoding.WriteString("CERTIFICATE REQUEST", bytes),
                cancellationToken: TestContext.Current.CancellationToken) as SignCertificateResponse.Success;

        Assert.Equal(GetParts(req.SubjectName), GetParts(cert!.Certificate.SubjectName));
        return;

        static IEnumerable<string> GetParts(X500DistinguishedName name)
        {
            return name.Name.Split(',').Select(x => x.Trim()).OrderBy(x => x);
        }
    }

    [Fact]
    public async Task CanCreateStringCertificateRequest()
    {
        using var rsa = RSA.Create(2048);

        var req = CreateCertificateRequest(rsa);
        var b64 = req.ToPkcs10Pem();
        var cert =
            await _authority.SignCertificateRequestPem(b64, cancellationToken: TestContext.Current.CancellationToken) as
                SignCertificateResponse.Success;

        Assert.Equal(
            string.Join("",
                req.SubjectName.Format(true).Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                    .OrderBy(x => x)),
            string.Join("",
                cert!.Certificate.SubjectName.Format(true)
                    .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).OrderBy(x => x)));
    }

    [Fact]
    public async Task IssuedCertificateHasAuthorityKeyIdentifierOfIssuer()
    {
        using var rsa = RSA.Create(2048);

        var req = CreateCertificateRequest(rsa);
        var response =
            await _authority.SignCertificateRequestPem(
                req.ToPkcs10Pem(),
                cancellationToken: TestContext.Current.CancellationToken) as SignCertificateResponse.Success;

        var issued = response!.Certificate;
        var issuer = response.Issuers[0];

        var aki = issued.Extensions.OfType<X509AuthorityKeyIdentifierExtension>().Single();
        var ski = issuer.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single();

        Assert.NotNull(aki.KeyIdentifier);
        Assert.Equal(
            Convert.ToHexString(ski.SubjectKeyIdentifierBytes.Span),
            Convert.ToHexString(aki.KeyIdentifier!.Value.Span));
    }

    [Fact]
    public async Task IssuedCertificateChainsToIssuer()
    {
        using var rsa = RSA.Create(2048);

        var req = CreateCertificateRequest(rsa);
        var response =
            await _authority.SignCertificateRequestPem(
                req.ToPkcs10Pem(),
                cancellationToken: TestContext.Current.CancellationToken) as SignCertificateResponse.Success;

        using var chain = new X509Chain();
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreNotTimeValid;
        chain.ChainPolicy.CustomTrustStore.AddRange(response!.Issuers);

        var built = chain.Build(response.Certificate);

        Assert.True(
            built,
            string.Join(", ", chain.ChainStatus.Select(s => s.StatusInformation.Trim())));
    }

    [Fact]
    public async Task CsrWithCaTrueIsRejected()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Evil CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

        var response = await _authority.SignCertificateRequestPem(
            req.ToPkcs10Pem(),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.IsType<SignCertificateResponse.Error>(response);
    }

    [Fact]
    public async Task CsrWithKeyCertSignIsRejected()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Evil CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature, true));

        var response = await _authority.SignCertificateRequestPem(
            req.ToPkcs10Pem(),
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.IsType<SignCertificateResponse.Error>(response);
    }

    [Fact]
    public async Task IssuedCertificateAlwaysHasBasicConstraintsLeafAndSkiRegardlessOfCsr()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test Leaf", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        var response = await _authority.SignCertificateRequestPem(
            req.ToPkcs10Pem(),
            cancellationToken: TestContext.Current.CancellationToken) as SignCertificateResponse.Success;

        var issued = response!.Certificate;

        var bc = issued.Extensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        Assert.NotNull(bc);
        Assert.False(bc.CertificateAuthority);
        Assert.True(bc.Critical);

        var ski = issued.Extensions.OfType<X509SubjectKeyIdentifierExtension>().SingleOrDefault();
        Assert.NotNull(ski);
    }

    [Fact]
    public async Task ExtensionsNotInAllowedListAreDroppedFromIssuedCertificate()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Test Leaf", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        // Certificate policies (2.5.29.32) is not in the default allowed list
        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
        req.CertificateExtensions.Add(
            new X509Extension(new Oid("2.5.29.32"), [0x30, 0x00], false));

        var response = await _authority.SignCertificateRequestPem(
            req.ToPkcs10Pem(),
            cancellationToken: TestContext.Current.CancellationToken) as SignCertificateResponse.Success;

        var issued = response!.Certificate;

        // EKU (2.5.29.37) is in the default allowed list — should be present
        Assert.NotNull(issued.Extensions["2.5.29.37"]);
        // Certificate policies (2.5.29.32) is not in the allowed list — should be absent
        Assert.Null(issued.Extensions["2.5.29.32"]);
    }

    [Fact]
    public async Task ProfileWithCaExtensionsAllowedCanIssueCaCertificate()
    {
        using var rsa = RSA.Create(3072);
        var caReq = new CertificateRequest(
            "CN=Intermediate CA",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        caReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        caReq.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        // Build a fresh authority whose default "rsa" profile permits CA extension copying.
        using var issuerRsa = RSA.Create(4096);
        var issuerReq = new CertificateRequest(
            "CN=Issuing CA",
            issuerRsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        issuerReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(issuerReq.PublicKey, false));
        var issuerCert = issuerReq.CreateSelfSigned(DateTimeOffset.UtcNow.Date, DateTimeOffset.UtcNow.Date.AddYears(5));

        using var authority = new CertificateAuthority(
            new CaConfiguration(
                new CaProfileSet(
                    "rsa",
                    new CaProfile
                    {
                        Name = "rsa",
                        PrivateKey = issuerRsa,
                        CertificateChain = [X509Certificate2.CreateFromPem(issuerCert.ExportCertificatePem())],
                        CertificateValidity = TimeSpan.FromDays(90),
                        // Allow basicConstraints and keyUsage to enable CA issuance
                        AllowedCsrExtensions = ["2.5.29.17", "2.5.29.37", "2.5.29.19", "2.5.29.15"]
                    }),
                [],
                [],
                []),
            new InMemoryCertificateStore(),
            new ValidateAll(),
            new RandomNumberCertificateIdGenerator(),
            new NullLogger<CertificateAuthority>());

        var response = await authority.SignCertificateRequestPem(
            caReq.ToPkcs10Pem(),
            cancellationToken: TestContext.Current.CancellationToken) as SignCertificateResponse.Success;

        Assert.NotNull(response);
        var bc = response.Certificate.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        Assert.True(bc.CertificateAuthority);
        var ku = response.Certificate.Extensions.OfType<X509KeyUsageExtension>().Single();
        Assert.True((ku.KeyUsages & X509KeyUsageFlags.KeyCertSign) != 0);
    }

    private static CertificateRequest CreateCertificateRequest(RSA rsa)
    {
        var req = new CertificateRequest(
            "CN=Test, OU=Test Department",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                false,
                false,
                0,
                false));

        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                false));

        // Time stamping
        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.8")], true));

        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req;
    }

    public void Dispose()
    {
        _authority.Dispose();
    }
}
