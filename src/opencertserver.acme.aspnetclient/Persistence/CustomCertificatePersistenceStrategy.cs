namespace OpenCertServer.Acme.AspNetClient.Persistence
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    public sealed class CustomCertificatePersistenceStrategy : ICertificatePersistenceStrategy
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

		public Task Persist(CertificateType persistenceType, byte[] certificate)
		{
			return _persist(persistenceType, certificate);
		}

		public async Task<byte[]?> RetrieveAccountCertificate()
		{
			var bytes = await _retrieve(CertificateType.Account);
			return bytes;
        }

		public async Task<X509Certificate2?> RetrieveSiteCertificate()
		{
			var bytes = await _retrieve(CertificateType.Account);
			return bytes == null ? null : new X509Certificate2(bytes);
        }
	}
}
