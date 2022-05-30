namespace OpenCertServer.Acme.AspNetClient.Tests
{
    using System;
    using System.Threading.Tasks;
    using Certificates;
    using global::Certes;
    using Persistence;
    using Xunit;

    public class CustomCertificatePersistence
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
            var retrievedCert = (AccountKeyCertificate?)await Strategy.RetrieveAccountCertificate();
            Assert.Null(retrievedCert);
        }

        [Fact]
        public async Task MissingSiteCertificateReturnsNull()
        {
            var retrievedCert = (LetsEncryptX509Certificate?)await Strategy.RetrieveSiteCertificate();
            Assert.Null(retrievedCert);
        }

        [Fact]
        public async Task AccountCertificateRoundTrip()
        {
            var testCert = new AccountKeyCertificate(KeyFactory.NewKey(KeyAlgorithm.ES256));
            KeyFactory.NewKey(KeyAlgorithm.ES256);

            await Strategy.Persist(CertificateType.Account, testCert);

            var retrievedCert = (AccountKeyCertificate?)await Strategy.RetrieveAccountCertificate();

            Assert.Equal(testCert.RawData, retrievedCert?.RawData);
        }

        [Fact]
        public async Task SiteCertificateRoundTrip()
        {
            var testCert = SelfSignedCertificate.Make(new DateTime(2020, 5, 24), new DateTime(2020, 5, 26));
            ;

            await Strategy.Persist(CertificateType.Site, testCert);

            var retrievedCert = (LetsEncryptX509Certificate?)await Strategy.RetrieveSiteCertificate();

            Assert.Equal(testCert.RawData, retrievedCert?.RawData);
        }
    }
}
