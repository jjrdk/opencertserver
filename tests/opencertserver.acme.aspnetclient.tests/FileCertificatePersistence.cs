namespace OpenCertServer.Acme.AspNetClient.Tests
{
    using System;
    using System.IO;
    using System.Text;
    using System.Threading.Tasks;
    using FluentAssertions;
    using global::Certes;
    using Persistence;
    using Xunit;

    public sealed class FileCertificatePersistence : IDisposable
    {
        private readonly string _testFolder;
        private ICertificatePersistenceStrategy Strategy { get; }

        public FileCertificatePersistence()
        {
            _testFolder = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
            Strategy = new FileCertificatePersistenceStrategy(_testFolder);
        }

        public void Dispose()
        {
            try
            {
                Directory.Delete(_testFolder, true);
            }
            catch
            {
            }
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

            retrievedCert.Should().Equal(testCert);
        }

        [Fact]
        public async Task SiteCertificateRoundTrip()
        {
            var testCert = SelfSignedCertificate.Make(new DateTime(2020, 5, 24), new DateTime(2020, 5, 26));

            await Strategy.Persist(CertificateType.Site, testCert.RawData);

            var retrievedCert = await Strategy.RetrieveSiteCertificate();

            testCert.RawData.Should().Equal(retrievedCert?.RawData);
        }
    }
}
