namespace OpenCertServer.Acme.AspNetClient.Tests
{
    using System;
    using System.Threading.Tasks;
    using global::Certes;
    using Microsoft.Extensions.Logging.Abstractions;
    using Persistence;
    using Xunit;

    public class PersistenceServiceTests
    {
        private IPersistenceService PersistenceService { get; set; } = null!;
        
        public PersistenceServiceTests()
        {
            PersistenceService = new PersistenceService(
                new[] {new MemoryCertificatePersistenceStrategy()},
                new[] {new MemoryChallengePersistenceStrategy()},
                NullLogger<IPersistenceService>.Instance);
        }

        [Fact]
        public async Task MissingAccountCertificateReturnsNull()
        {
            Assert.Null(await PersistenceService.GetPersistedAccountCertificate());
        }

        [Fact]
        public async Task MissingSiteCertificateReturnsNull()
        {
            Assert.Null(await PersistenceService.GetPersistedSiteCertificate());
        }
       
        [Fact]
        public async Task AccountCertificateRoundTrip()
        {
            var key = KeyFactory.NewKey(KeyAlgorithm.ES256);

            await PersistenceService.PersistAccountCertificate(key);

            var retrievedKey = await PersistenceService.GetPersistedAccountCertificate();
            
            Assert.Equal(key.ToPem(), retrievedKey?.ToPem());
        }

        [Fact]
        public async Task SiteCertificateRoundTrip()
        {
            var testCert = SelfSignedCertificate.Make(new DateTime(2020, 5, 24), new DateTime(2020, 5, 26));; 

            await PersistenceService.PersistSiteCertificate(testCert);

            var retrievedCert = await PersistenceService.GetPersistedSiteCertificate();
            
            Assert.Equal(testCert.RawData, retrievedCert?.RawData);
        }
    }
}