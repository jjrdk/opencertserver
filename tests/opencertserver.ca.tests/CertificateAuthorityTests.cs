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
        _authority = new CertificateAuthority(
            new CaConfiguration(
                new CaProfileSet(
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
                ),
                ["test"],
                [],
                []),
            new InMemoryCertificateStore(),
            new ValidateAll(),
            new RandomNumberCertificateIdGenerator(),
            new NullLogger<CertificateAuthority>());
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

    // A CSR used to be able to ask for basicConstraints CA:TRUE and keyCertSign and got
    // exactly that - a working subordinate CA for anyone allowed to enroll.
    [Fact]
    public async Task RequestForCaCertificateIsRefused()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Wants to be a CA", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));

        var response = await _authority.SignCertificateRequest(req, "rsa",
            cancellationToken: TestContext.Current.CancellationToken);

        var error = Assert.IsType<SignCertificateResponse.Error>(response);
        Assert.Contains("CA certificate", string.Join(" ", error.Errors));
    }

    [Fact]
    public async Task RequestForKeyCertSignIsRefused()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Wants keyCertSign", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

        var response = await _authority.SignCertificateRequest(req, "rsa",
            cancellationToken: TestContext.Current.CancellationToken);

        Assert.IsType<SignCertificateResponse.Error>(response);
    }

    [Fact]
    public async Task IssuedCertificateIsEndEntityWithOwnSubjectKeyIdentifier()
    {
        // A bare request without basicConstraints and SKI: both come from the CA.
        using var rsa = RSA.Create(2048);
        var bare = new CertificateRequest("CN=Bare", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var response = await _authority.SignCertificateRequest(bare, "rsa",
            cancellationToken: TestContext.Current.CancellationToken) as SignCertificateResponse.Success;

        var basic = response!.Certificate.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        Assert.False(basic.CertificateAuthority);
        Assert.True(basic.Critical);
        var ski = response.Certificate.Extensions.OfType<X509SubjectKeyIdentifierExtension>().Single();
        Assert.Equal(
            new X509SubjectKeyIdentifierExtension(response.Certificate.PublicKey, false).SubjectKeyIdentifier,
            ski.SubjectKeyIdentifier);
    }

    // A request that already says CA:FALSE and brings a SKI of its own gets exactly one of
    // each, from the CA.
    [Fact]
    public async Task RequestedBasicConstraintsAndSkiAreReplacedNotDuplicated()
    {
        using var rsa = RSA.Create(2048);
        var req = CreateCertificateRequest(rsa);
        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension([1, 2, 3, 4], false));

        var response = await _authority.SignCertificateRequest(req, "rsa",
            cancellationToken: TestContext.Current.CancellationToken) as SignCertificateResponse.Success;
        var extensions = response!.Certificate.Extensions.Cast<X509Extension>().ToArray();

        Assert.Single(extensions, e => e.Oid?.Value == "2.5.29.19");
        var ski = Assert.Single(extensions.OfType<X509SubjectKeyIdentifierExtension>());
        Assert.NotEqual("01020304", ski.SubjectKeyIdentifier);
    }

    // Policies, name constraints and the policy-processing extensions are the CA's to set:
    // ones the requester brings along are dropped.
    [Theory]
    [InlineData("2.5.29.32", new byte[] { 0x30, 0x06, 0x30, 0x04, 0x06, 0x02, 0x2A, 0x03 })] // certificatePolicies
    [InlineData("2.5.29.30", new byte[] { 0x30, 0x0B, 0xA0, 0x09, 0x30, 0x07, 0x82, 0x05, 0x2E, 0x74, 0x65, 0x73, 0x74 })] // nameConstraints
    [InlineData("2.5.29.36", new byte[] { 0x30, 0x03, 0x80, 0x01, 0x00 })] // policyConstraints
    [InlineData("2.5.29.54", new byte[] { 0x02, 0x01, 0x00 })] // inhibitAnyPolicy
    public async Task CaOnlyExtensionFromRequestIsNotTakenOver(string oid, byte[] value)
    {
        using var rsa = RSA.Create(2048);
        var req = CreateCertificateRequest(rsa);
        req.CertificateExtensions.Add(new X509Extension(new Oid(oid), value, false));

        var response = await _authority.SignCertificateRequest(req, "rsa",
            cancellationToken: TestContext.Current.CancellationToken) as SignCertificateResponse.Success;

        Assert.DoesNotContain(response!.Certificate.Extensions.Cast<X509Extension>(), e => e.Oid?.Value == oid);
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
