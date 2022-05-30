namespace OpenCertServer.Acme.AspNetClient.Persistence
{
    using System.IO;
    using System.Threading.Tasks;
    using Certificates;

    public class FileCertificatePersistenceStrategy : ICertificatePersistenceStrategy
    {
        private readonly string _relativeFilePath;

        public FileCertificatePersistenceStrategy(string relativeFilePath)
        {
            _relativeFilePath = relativeFilePath;
        }

        public Task Persist(CertificateType persistenceType, IPersistableCertificate certificate)
        {
            return File.WriteAllBytesAsync(GetCertificatePath(persistenceType), certificate.RawData);
        }

        public async Task<IKeyCertificate?> RetrieveAccountCertificate()
        {
            var bytes = await ReadFile(CertificateType.Account);
            return bytes == null ? null : new AccountKeyCertificate(bytes);
        }

        public async Task<IAbstractCertificate?> RetrieveSiteCertificate()
        {
            var bytes = await ReadFile(CertificateType.Site);
            return bytes == null ? null : new LetsEncryptX509Certificate(bytes);
        }

        private async Task<byte[]?> ReadFile(CertificateType persistenceType)
        {
            return !File.Exists(GetCertificatePath(persistenceType))
                ? null
                : await File.ReadAllBytesAsync(GetCertificatePath(persistenceType));
        }

        private string GetCertificatePath(CertificateType persistenceType)
        {
            return _relativeFilePath + "_" + persistenceType;
        }
    }
}
