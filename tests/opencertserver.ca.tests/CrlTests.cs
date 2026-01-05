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
        using var ecdsa = ECDsa.Create();
        var certRequest = new CertificateRequest(
            "CN=Test CA,C=US",
            ecdsa,
            HashAlgorithmName.SHA256);
        certRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        var certificate = certRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1));
        var crlBuilder = new CertificateRevocationListBuilder();
        crlBuilder.AddEntry("1"u8, DateTimeOffset.UtcNow, X509RevocationReason.KeyCompromise);
        var crl = crlBuilder.Build(
            certificate,
            1,
            DateTimeOffset.UtcNow.AddDays(1),
            HashAlgorithmName.SHA256);
        var loadedCrl = CertificateRevocationList.Load(crl);

        Assert.Equal("C=US, CN=Test CA", loadedCrl.Issuer.Name);
        Assert.Single(loadedCrl.RevokedCertificates);
    }
}
