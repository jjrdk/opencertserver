using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509Extensions;
using Xunit;

namespace OpenCertServer.Ca.Tests;

public class CrlTests
{
    [Fact]
    public void CanReadCrlPem()
    {
        const string pem = """
                           -----BEGIN X509 CRL-----
                           MIIDFDCCAfwCAQEwDQYJKoZIhvcNAQEFBQAwXzEjMCEGA1UEChMaU2FtcGxlIFNp
                           Z25lciBPcmdhbml6YXRpb24xGzAZBgNVBAsTElNhbXBsZSBTaWduZXIgVW5pdDEb
                           MBkGA1UEAxMSU2FtcGxlIFNpZ25lciBDZXJ0Fw0xMzAyMTgxMDMyMDBaFw0xMzAy
                           MTgxMDQyMDBaMIIBNjA8AgMUeUcXDTEzMDIxODEwMjIxMlowJjAKBgNVHRUEAwoB
                           AzAYBgNVHRgEERgPMjAxMzAyMTgxMDIyMDBaMDwCAxR5SBcNMTMwMjE4MTAyMjIy
                           WjAmMAoGA1UdFQQDCgEGMBgGA1UdGAQRGA8yMDEzMDIxODEwMjIwMFowPAIDFHlJ
                           Fw0xMzAyMTgxMDIyMzJaMCYwCgYDVR0VBAMKAQQwGAYDVR0YBBEYDzIwMTMwMjE4
                           MTAyMjAwWjA8AgMUeUoXDTEzMDIxODEwMjI0MlowJjAKBgNVHRUEAwoBATAYBgNV
                           HRgEERgPMjAxMzAyMTgxMDIyMDBaMDwCAxR5SxcNMTMwMjE4MTAyMjUxWjAmMAoG
                           A1UdFQQDCgEFMBgGA1UdGAQRGA8yMDEzMDIxODEwMjIwMFqgLzAtMB8GA1UdIwQY
                           MBaAFL4SAcyq6hGA2i6tsurHtfuf+a00MAoGA1UdFAQDAgEDMA0GCSqGSIb3DQEB
                           BQUAA4IBAQBCIb6B8cN5dmZbziETimiotDy+FsOvS93LeDWSkNjXTG/+bGgnrm3a
                           QpgB7heT8L2o7s2QtjX2DaTOSYL3nZ/Ibn/R8S0g+EbNQxdk5/la6CERxiRp+E2T
                           UG8LDb14YVMhRGKvCguSIyUG0MwGW6waqVtd6K71u7vhIU/Tidf6ZSdsTMhpPPFu
                           PUid4j29U3q10SGFF6cCt1DzjvUcCwHGhHA02Men70EgZFADPLWmLg0HglKUh1iZ
                           WcBGtev/8VsUijyjsM072C6Ut5TwNyrrthb952+eKlmxLNgT0o5hVYxjXhtwLQsL
                           7QZhrypAM1DLYqQjkiDI7hlvt7QuDGTJ
                           -----END X509 CRL-----
                           """;
        var crl = CertificateRevocationList.LoadPem(pem.AsSpan());
        Assert.NotEmpty(crl.RevokedCertificates);
    }

    [Theory]
    [InlineData("RSA")]
    [InlineData("ECDSA")]
    public void CanBuildCrlAndReadBack(string algorithmType)
    {
        var hashAlgorithmName = HashAlgorithmName.SHA256;
        var certificate = algorithmType switch
        {
            "RSA" => GetRsaCertificate(hashAlgorithmName),
            "ECDSA" => GetEcDsaCertificate(hashAlgorithmName),
            _ => throw new ArgumentOutOfRangeException(nameof(algorithmType), algorithmType, null)
        };
        var crl = new CertificateRevocationList(
            CertificateRevocationList.CrlVersion.V2,
            hashAlgorithmName,
            certificate.SubjectName,
            DateTimeOffset.UtcNow,
            DateTimeOffset.UtcNow.AddDays(1),
            [
                new RevokedCertificate(
                    new BigInteger(128).ToByteArray(),
                    DateTimeOffset.UtcNow,
                    new CertificateExtension(
                        new Oid("2.5.29.21"),
                        X509RevocationReason.KeyCompromise,
                        null,
                        null,
                        false),
                    new CertificateExtension(
                        new Oid("2.5.29.29"),
                        null,
                        certificate.SubjectName,
                        null,
                        false),
                    new CertificateExtension(new Oid("2.5.29.24"),
                        null,
                        null,
                        DateTimeOffset.UtcNow,
                        false))
            ],
            [
                new X509CrlNumberExtension(BigInteger.One, false),
                new X509AuthorityInformationAccessExtension(["test"],[])
            ]);
        AsymmetricAlgorithm privateKey = algorithmType switch
        {
            "RSA" => certificate.GetRSAPrivateKey()!,
            "ECDSA" => certificate.GetECDsaPrivateKey()!,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithmType), algorithmType, null)
        };
        var crlBytes = crl.Build(hashAlgorithmName, privateKey);
        AsymmetricAlgorithm publicKey = algorithmType switch
        {
            "RSA" => certificate.GetRSAPublicKey()!,
            "ECDSA" => certificate.GetECDsaPublicKey()!,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithmType), algorithmType, null)
        };
        var loadedCrl = CertificateRevocationList.Load(crlBytes, publicKey);

        Assert.Equal(BigInteger.One, loadedCrl.CrlNumber);
        Assert.Single(loadedCrl.RevokedCertificates);
        Assert.Equal(3, loadedCrl.RevokedCertificates.First().Extensions.Count);
        Assert.Equal(2, loadedCrl.Extensions.Count);
    }

    [Fact]
    public void CanReadCrl()
    {
        var hashAlgorithmName = HashAlgorithmName.SHA256;
        var certificate = GetEcDsaCertificate(hashAlgorithmName);
        var crl = GetCrl(certificate, hashAlgorithmName);
        var loadedCrl = CertificateRevocationList.Load(crl, certificate.GetECDsaPublicKey()!);

        Assert.Equal("C=US, CN=Test CA", loadedCrl.Issuer.Name);
        Assert.Single(loadedCrl.RevokedCertificates);
        Assert.Equal(X509RevocationReason.KeyCompromise,
            loadedCrl.RevokedCertificates.First().Extensions.First().Reason);
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
