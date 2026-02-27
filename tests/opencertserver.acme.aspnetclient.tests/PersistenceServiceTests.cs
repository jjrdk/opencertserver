using Microsoft.IdentityModel.Tokens;

namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.Threading.Tasks;
using CertesSlim;
using Microsoft.Extensions.Logging.Abstractions;
using Persistence;
using Xunit;

public sealed class PersistenceServiceTests
{
    private IPersistenceService PersistenceService { get; }

    public PersistenceServiceTests()
    {
        PersistenceService = new PersistenceService(
            [new InMemoryCertificatePersistenceStrategy()],
            [new InMemoryChallengePersistenceStrategy()],
            NullLogger<PersistenceService>.Instance);
    }

    [Fact]
    public async Task MissingAccountCertificateReturnsNull()
    {
        Assert.Null(await PersistenceService.GetPersistedAccountCertificate());
    }

    [Fact]
    public async Task MissingSiteCertificateReturnsNull()
    {
        Assert.Null(await PersistenceService.GetPersistedSiteCertificate(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task AccountCertificateRoundTrip()
    {
        var key = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);

        await PersistenceService.PersistAccountCertificate(key);

        var retrievedKey = await PersistenceService.GetPersistedAccountCertificate();

        Assert.Equal(key.ToPem(), retrievedKey?.ToPem());
    }

    [Fact]
    public async Task SiteCertificateRoundTrip()
    {
        var testCert = SelfSignedCertificate.Make(new DateTime(2020, 5, 24), new DateTime(2020, 5, 26));

        await PersistenceService.PersistSiteCertificate(testCert, TestContext.Current.CancellationToken);

        var retrievedCert = await PersistenceService.GetPersistedSiteCertificate(TestContext.Current.CancellationToken);

        Assert.Equal(testCert.RawData, retrievedCert?.RawData);
    }
}
