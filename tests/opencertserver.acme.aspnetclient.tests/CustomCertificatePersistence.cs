namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.Text;
using System.Threading.Tasks;
using global::Certes;
using Persistence;
using Xunit;

public sealed class CustomCertificatePersistence
{
    private ICertificatePersistenceStrategy Strategy { get; }

    public CustomCertificatePersistence()
    {
        byte[]? store = null;
        Strategy = new CustomCertificatePersistenceStrategy(
            (_, data) =>
            {
                store = data;
                return Task.CompletedTask;
            },
            _ => Task.FromResult(store));
    }

    [Fact]
    public async Task MissingAccountCertificateReturnsNull()
    {
        var retrievedCert = await Strategy.RetrieveAccountCertificate();
        Assert.Null(retrievedCert);
    }

    [Fact]
    public async Task MissingSiteCertificateReturnsNull()
    {
        var retrievedCert = await Strategy.RetrieveSiteCertificate();
        Assert.Null(retrievedCert);
    }

    [Fact]
    public async Task AccountCertificateRoundTrip()
    {
        var testCert = Encoding.UTF8.GetBytes(KeyFactory.NewKey(KeyAlgorithm.ES256).ToPem());
        KeyFactory.NewKey(KeyAlgorithm.ES256);

        await Strategy.Persist(CertificateType.Account, testCert);

        var retrievedCert = await Strategy.RetrieveAccountCertificate();

        Assert.Equal(testCert, retrievedCert!);
    }

    [Fact]
    public async Task SiteCertificateRoundTrip()
    {
        var testCert = SelfSignedCertificate.Make(new DateTime(2020, 5, 24), new DateTime(2020, 5, 26));

        await Strategy.Persist(CertificateType.Site, testCert.RawData);

        var retrievedCert = await Strategy.RetrieveSiteCertificate();

        Assert.Equal(testCert.RawData, retrievedCert?.RawData);
    }
}