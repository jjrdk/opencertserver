namespace OpenCertServer.Acme.AspNetClient.Persistence
{
    using System.Threading.Tasks;
    using Certificates;

    public interface ICertificatePersistenceStrategy
	{
		/// <summary>
		/// Optional. The async method to use for persisting some data for later use (if server restarts).
		/// </summary>
		Task Persist(CertificateType persistenceType, IPersistableCertificate certificate);
		
		/// <summary>
		/// Optional. The async method to use for fetching previously generated data for a given key.
		/// </summary>
		Task<IKeyCertificate?> RetrieveAccountCertificate();

		/// <summary>
		/// Optional. The async method to use for fetching previously generated data for a given key.
		/// </summary>
		Task<IAbstractCertificate?> RetrieveSiteCertificate();
	}
}
