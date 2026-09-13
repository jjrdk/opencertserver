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
    /// Persists the full site certificate with its private key when available. The default
    /// implementation extracts the raw DER bytes and delegates to <see cref="Persist"/>.
    /// Override this method in strategies that can store the private key (e.g. an OS certificate store).
    /// </summary>
    Task PersistSiteCertificate(X509Certificate2 certificate)
           => Persist(CertificateType.Site, certificate.RawData);

    /// <summary>
    /// Persists the leaf/chain/key for <paramref name="routeId"/> from a full certificate
    /// collection (leaf first, followed by the issuers). The issuer certificates are written to
    /// the route's <c>chains</c> directory so downstream tooling can read a real chain; the
    /// default delegates to the leaf-only <see cref="PersistSiteCertificate(X509Certificate2, string)"/>.
    /// </summary>
    Task PersistSiteCertificateChain(X509Certificate2Collection chain, string routeId)
          => PersistSiteCertificate(chain[0], routeId);

    /// <summary>
    /// Persists the full site certificate scoped to <paramref name="routeId"/>. Implementors that
    /// support per-route storage must override this method.
    /// </summary>
    /// <remarks>
    /// The default implementation throws <see cref="System.NotSupportedException"/> so that a
    /// strategy which does not support per-route storage fails loudly at runtime instead of
    /// silently collapsing every route's certificate onto a single key.
    /// </remarks>
    Task PersistSiteCertificate(X509Certificate2 certificate, string routeId)
        => throw new System.NotSupportedException(
            $"{GetType().Name} does not support route-scoped certificate persistence. Override PersistSiteCertificate(X509Certificate2, string) to support per-route storage.");

    /// <summary>
    /// Optional. The async method to use for fetching previously generated data for a given key.
    /// </summary>
    Task<byte[]?> RetrieveAccountCertificate();

    /// <summary>
    /// Optional. The async method to use for fetching previously generated data for a given key.
    /// </summary>
    Task<X509Certificate2?> RetrieveSiteCertificate();

    /// <summary>
    /// Retrieves the persisted site certificate scoped to <paramref name="routeId"/>. The default
    /// implementation delegates to the non-scoped overload, preserving back-compat.
    /// </summary>
    Task<X509Certificate2?> RetrieveSiteCertificate(string routeId)
         => RetrieveSiteCertificate();

    /// <summary>
    /// Returns the PEM-encoded leaf private key previously persisted for <paramref name="routeId"/>,
    /// or null when this strategy does not keep route-scoped keys. Strategies that store a
    /// route-scoped key (e.g. the file strategy) override this so the renewal engine can reuse the
    /// key across renewals.
    /// </summary>
    Task<string?> GetPersistedRouteKey(string routeId, System.Threading.CancellationToken cancellationToken = default)
         => Task.FromResult<string?>(null);

    /// <summary>
    /// Persists the PEM-encoded leaf private key for <paramref name="routeId"/>. The default is a
    /// no-op for strategies that do not keep route-scoped keys.
    /// </summary>
    Task PersistRouteKey(string routeId, string keyPem, System.Threading.CancellationToken cancellationToken = default)
         => Task.CompletedTask;
}
