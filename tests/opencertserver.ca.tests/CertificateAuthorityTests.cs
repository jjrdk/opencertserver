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
            new NullLogger<CertificateAuthority>());
    }

    [Fact]
    public async Task CanSerializeCertificateRequest()
    {
        using var rsa = RSA.Create(2048);

        var req = CreateCertificateRequest(rsa);
        var bytes = req.CreateSigningRequest();
        var cert =
            (await _authority.SignCertificateRequestPem(
                PemEncoding.WriteString("CERTIFICATE REQUEST", bytes),
                cancellationToken: CancellationToken.None)) as SignCertificateResponse.Success;

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
        var b64 = req.ToPkcs10();
        var cert =
            await _authority.SignCertificateRequestPem(b64, cancellationToken: CancellationToken.None) as
                SignCertificateResponse.Success;

        Assert.Equal(
            string.Join("",
                req.SubjectName.Format(true).Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries)
                    .OrderBy(x => x)),
            string.Join("",
                cert!.Certificate.SubjectName.Format(true)
                    .Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).OrderBy(x => x)));
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
            new X509EnhancedKeyUsageExtension([new("1.3.6.1.5.5.7.3.8")], true));

        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req;
    }

    public void Dispose()
    {
        (_authority as IDisposable)?.Dispose();
    }
}
