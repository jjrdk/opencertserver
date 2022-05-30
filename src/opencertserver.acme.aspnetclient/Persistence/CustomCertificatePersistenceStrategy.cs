namespace OpenCertServer.Acme.AspNetClient.Persistence
{
    using System;
    using System.Threading.Tasks;
    using Certificates;

    public class CustomCertificatePersistenceStrategy : ICertificatePersistenceStrategy
	{
		private readonly Func<CertificateType, byte[], Task> _persist;
		private readonly Func<CertificateType, Task<byte[]?>> _retrieve;

		public CustomCertificatePersistenceStrategy(
			Func<CertificateType, byte[], Task> persist,
			Func<CertificateType, Task<byte[]?>> retrieve)
		{
			_persist = persist;
			_retrieve = retrieve;
		}

		public Task Persist(CertificateType persistenceType, IPersistableCertificate certificate)
		{
			return _persist(persistenceType, certificate.RawData);
		}

		public async Task<IKeyCertificate?> RetrieveAccountCertificate()
		{
			var bytes = await _retrieve(CertificateType.Account);
			return bytes == null ? null : new AccountKeyCertificate(bytes);
        }

		public async Task<IAbstractCertificate?> RetrieveSiteCertificate()
		{
			var bytes = await _retrieve(CertificateType.Account);
			if (bytes == null)
			{
				return null;
			}
			return new LetsEncryptX509Certificate(bytes);
		}
	}
}
