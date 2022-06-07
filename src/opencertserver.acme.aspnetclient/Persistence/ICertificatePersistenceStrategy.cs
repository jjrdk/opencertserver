namespace OpenCertServer.Acme.AspNetClient.Persistence
{
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    public interface ICertificatePersistenceStrategy
	{
		/// <summary>
		/// Optional. The async method to use for persisting some data for later use (if server restarts).
		/// </summary>
		Task Persist(CertificateType persistenceType, byte[] certificate);
		
		/// <summary>
		/// Optional. The async method to use for fetching previously generated data for a given key.
		/// </summary>
		Task<byte[]?> RetrieveAccountCertificate();

		/// <summary>
		/// Optional. The async method to use for fetching previously generated data for a given key.
		/// </summary>
		Task<X509Certificate2?> RetrieveSiteCertificate();
	}
}
