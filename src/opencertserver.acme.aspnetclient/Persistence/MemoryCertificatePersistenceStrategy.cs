namespace OpenCertServer.Acme.AspNetClient.Persistence
{
    using System;
    using System.Threading.Tasks;
    using Certificates;

    public class MemoryCertificatePersistenceStrategy : ICertificatePersistenceStrategy
	{
        private IKeyCertificate? _accountCertificate;
        private IAbstractCertificate? _siteCertificate;

		public Task Persist(CertificateType persistenceType, IPersistableCertificate certificate)
		{
			switch (persistenceType)
			{
				case CertificateType.Account:
					_accountCertificate = (IKeyCertificate)certificate;
					break;
				case CertificateType.Site:
					_siteCertificate = certificate;
					break;
				default:
					throw new ArgumentException("Unhandled persistence type", nameof(persistenceType));
			}
			return Task.CompletedTask;
		}

		public Task<IKeyCertificate?> RetrieveAccountCertificate()
		{
			return Task.FromResult(_accountCertificate);
		}

		public Task<IAbstractCertificate?> RetrieveSiteCertificate()
		{
			return Task.FromResult(_siteCertificate);
		}
	}
}
