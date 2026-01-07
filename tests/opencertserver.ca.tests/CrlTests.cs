using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using Xunit;

namespace OpenCertServer.Ca.Tests;

public class CrlTests
{
    [Fact]
    public void CanReadCrl()
    {
        var hashAlgorithmName = HashAlgorithmName.SHA256;
        var certificate = GetEcDsaCertificate(hashAlgorithmName);
        var crl = GetCrl(certificate, hashAlgorithmName);
        var loadedCrl = CertificateRevocationList.Load(crl, certificate.GetECDsaPublicKey()!);

        Assert.Equal("C=US, CN=Test CA", loadedCrl.Issuer.Name);
        Assert.Single(loadedCrl.RevokedCertificates);
    }

    [Fact]
    public void CanReadEcdsaCrlSignature()
    {
        var certificate = GetEcDsaCertificate(HashAlgorithmName.SHA256);
        var crl = GetCrl(certificate, HashAlgorithmName.SHA256);

        Assert.True(CertificateRevocationList.VerifyCrlSignature(crl, certificate.GetECDsaPublicKey()!));
    }

    [Fact]
    public void CanReadRsaCrlSignature()
    {
        var certificate = GetRsaCertificate(HashAlgorithmName.SHA256);
        var crl = GetCrl(certificate, HashAlgorithmName.SHA256);

        Assert.True(CertificateRevocationList.VerifyCrlSignature(crl, certificate.GetRSAPublicKey()!));
    }

    private static byte[] GetCrl(X509Certificate2 certificate, HashAlgorithmName hashAlgorithmName)
    {
        var crlBuilder = new CertificateRevocationListBuilder();
        crlBuilder.AddEntry("1"u8, DateTimeOffset.UtcNow, X509RevocationReason.KeyCompromise);
        var crl = crlBuilder.Build(
            certificate,
            1,
            DateTimeOffset.UtcNow.AddDays(1),
            hashAlgorithmName,
            RSASignaturePadding.Pss);
        return crl;
    }

    private static X509Certificate2 GetEcDsaCertificate(HashAlgorithmName hashAlgorithmName)
    {
        using var ecdsa = ECDsa.Create();
        var certRequest = new CertificateRequest(
            "CN=Test CA,C=US",
            ecdsa,
            hashAlgorithmName);
        certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.CrlSign, false));
        certRequest.CertificateExtensions.Add(
            CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([
                "http://crl.testca.local/testca.crl"
            ]));
        var certificate = certRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
        return certificate;
    }

    private static X509Certificate2 GetRsaCertificate(HashAlgorithmName hashAlgorithmName)
    {
        using var rsa = RSA.Create();
        var certRequest = new CertificateRequest(
            "CN=Test CA,C=US",
            rsa,
            hashAlgorithmName,
            RSASignaturePadding.Pss);
        certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        certRequest.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.CrlSign, false));
        certRequest.CertificateExtensions.Add(
            CertificateRevocationListBuilder.BuildCrlDistributionPointExtension([
                "http://crl.testca.local/testca.crl"
            ]));
        var certificate = certRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
        return certificate;
    }
}
