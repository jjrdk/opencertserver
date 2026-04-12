namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

public interface ICertificatePersistenceStrategy
{
    /// <summary>
    /// Optional. The async method to use for persisting some data for later use (if server restarts).
    /// </summary>
    Task Persist(CertificateType persistenceType, byte[] certificate);

    /// <summary>
    /// Persists the full site certificate, including the private key when available.
    /// The default implementation extracts the raw DER bytes and delegates to <see cref="Persist"/>.
    /// Override this method in strategies that can store the private key (e.g. an OS certificate store).
    /// </summary>
    Task PersistSiteCertificate(X509Certificate2 certificate)
        => Persist(CertificateType.Site, certificate.RawData);

    /// <summary>
    /// Optional. The async method to use for fetching previously generated data for a given key.
    /// </summary>
    Task<byte[]?> RetrieveAccountCertificate();

    /// <summary>
    /// Optional. The async method to use for fetching previously generated data for a given key.
    /// </summary>
    Task<X509Certificate2?> RetrieveSiteCertificate();
}
