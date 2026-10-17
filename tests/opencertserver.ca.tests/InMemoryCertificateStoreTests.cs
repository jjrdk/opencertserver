namespace OpenCertServer.Ca.Tests;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.Ca;
using Xunit;

public class InMemoryCertificateStoreTests
{
    private static X509Certificate2 SelfSigned(string subject)
    {
        using var key = RSA.Create(2048);
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }

    [Fact]
    public async Task FindsCertificatesByThumbprintAndBySerialNumber()
    {
        var store = new InMemoryCertificateStore();
        using var first = SelfSigned("CN=first");
        using var second = SelfSigned("CN=second");
        await store.AddCertificate(first, TestContext.Current.CancellationToken);
        await store.AddCertificate(second, TestContext.Current.CancellationToken);

        var byThumbprint = await store
            .GetCertificatesByThumbprint([second.Thumbprint.AsMemory()], TestContext.Current.CancellationToken)
            .ToListAsync(TestContext.Current.CancellationToken);
        var bySerial = await store
            .GetCertificatesById(TestContext.Current.CancellationToken, first.SerialNumberBytes)
            .ToListAsync(TestContext.Current.CancellationToken);

        Assert.Equal(second.Thumbprint, Assert.Single(byThumbprint).Thumbprint);
        Assert.Equal(first.Thumbprint, Assert.Single(bySerial).Thumbprint);
    }
}
