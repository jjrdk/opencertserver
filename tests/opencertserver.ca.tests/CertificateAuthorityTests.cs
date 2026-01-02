namespace OpenCertServer.Ca.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging.Abstractions;
using Utils;
using Xunit;

public sealed class CertificateAuthorityTests : IDisposable
{
    private readonly ICertificateAuthority _authority;

    public CertificateAuthorityTests()
    {
        using var ecdsa = ECDsa.Create();
        var ecdsaReq = new CertificateRequest("CN=Test Server", ecdsa, HashAlgorithmName.SHA256);
        ecdsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
        var ecdsaCert = ecdsaReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.Date,
            DateTimeOffset.UtcNow.Date.AddYears(1));
        using var rsa = RSA.Create(4096);
        var rsaReq = new CertificateRequest(
            "CN=Test Server",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        rsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
        var rsaCert = rsaReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.Date,
            DateTimeOffset.UtcNow.Date.AddYears(1));
        _authority = new CertificateAuthority(
            rsaCert,
            ecdsaCert,
            new InMemoryCertificateStore(ecdsaCert),
            TimeSpan.FromDays(90),
            _ => true,
            new NullLogger<CertificateAuthority>());
    }

    [Fact]
    public void CanSerializeCertificateRequest()
    {
        using var rsa = RSA.Create(2048);

        var req = CreateCertificateRequest(rsa);
        var bytes = req.CreateSigningRequest();
        var csr = Convert.ToBase64String(bytes);
        var cert = _authority.SignCertificateRequest(csr) as SignCertificateResponse.Success;

        static IEnumerable<string> GetParts(X500DistinguishedName name)
        {
            return name.Name.Split(',').Select(x => x.Trim()).OrderBy(x => x);
        }

        Assert.Equal(GetParts(req.SubjectName), GetParts(cert!.Certificate.SubjectName));
    }

    [Fact]
    public void CanCreateStringCertificateRequest()
    {
        using var rsa = RSA.Create(2048);

        var req = CreateCertificateRequest(rsa);
        var b64 = req.ToPkcs10();
        var cert = _authority.SignCertificateRequest(b64) as SignCertificateResponse.Success;

        Assert.Equal(
            string.Join("", req.SubjectName.Format(true).Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).OrderBy(x => x)),
            string.Join("", cert!.Certificate.SubjectName.Format(true).Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries).OrderBy(x => x)));
    }

    [Fact]
    public void WhenCreatingWithBackupActionThenBacksUpCerts()
    {
        X509Certificate2 rsa = null!;
        X509Certificate2 ecdsa = null!;
        var ca = CertificateAuthority.Create(
            new X500DistinguishedName("CN=test"),
            x=> new InMemoryCertificateStore(x),
            TimeSpan.FromDays(1),
            NullLogger<CertificateAuthority>.Instance,
            null,
            (c1, c2) =>
            {
                rsa = c1;
                ecdsa = c2;
            });

        Assert.NotNull(rsa);
        Assert.NotNull(ecdsa);
    }

    //[Fact]
    //public void WhenCreatingWithBackupActionThenBacksUpCerts2()
    //{
    //    using (var rsa = File.OpenWrite("rsa.pem"))
    //    {
    //        using var rsaKey = File.OpenWrite("rsa_key.pem");
    //        using var ecdsa = File.OpenWrite("ecdsa.pem");
    //        using var ecdsaKey = File.OpenWrite("ecdsa_key.pem");
    //        var ca = new CertificateAuthority(
    //            new X500DistinguishedName("CN=reimers.io,DC=reimers.io,O=OpenCertServer,C=Denmark"),
    //            TimeSpan.FromDays(2 * 365),
    //            c => true,
    //            NullLogger<CertificateAuthority>.Instance,
    //            (c1, c2) =>
    //            {
    //                rsa.Write(Encoding.UTF8.GetBytes(c1.ExportCertificatePem()));
    //                rsaKey.Write(Encoding.UTF8.GetBytes(c1.GetRSAPrivateKey().ExportRSAPrivateKeyPem()));

    //                ecdsa.Write(Encoding.UTF8.GetBytes(c2.ExportCertificatePem()));
    //                ecdsaKey.Write(Encoding.UTF8.GetBytes(c2.GetECDsaPrivateKey().ExportECPrivateKeyPem()));
    //            });
    //    }

    //    var ecdsaCert = X509Certificate2.CreateFromPemFile("ecdsa.pem", "ecdsa_key.pem");
    //    Assert.True(ecdsaCert.HasPrivateKey);
    //    var rsaCert = X509Certificate2.CreateFromPemFile("rsa.pem", "rsa_key.pem");
    //    Assert.True(rsaCert.HasPrivateKey);
    //}

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
