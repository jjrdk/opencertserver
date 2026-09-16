namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CertesSlim;

public interface IPersistenceService
{
    Task<IKey?> GetPersistedAccountCertificate();

    Task<ChallengeDto[]> GetPersistedChallenges();

    /// <summary>
    /// Retrieves the persisted site certificate for the default route. Preserves the legacy
    /// single-listener behaviour.
    /// </summary>
    Task<X509Certificate2?> GetPersistedSiteCertificate(CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the persisted site certificate scoped to <paramref name="routeId"/>.
    /// </summary>
    Task<X509Certificate2?> GetPersistedSiteCertificate(string routeId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists the site certificate for the default route, with a cancellation token.
    /// Preserves the legacy single-listener behaviour.
    /// </summary>
    Task PersistSiteCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists the site certificate scoped to <paramref name="routeId"/> so that each YARP
    /// route keeps its own leaf/chain/key. When <paramref name="routeId"/> is null the default
    /// route is used, preserving the legacy single-listener behaviour.
    /// </summary>
    Task PersistSiteCertificate(X509Certificate2 certificate, string? routeId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists the full certificate <paramref name="chain"/> (leaf followed by issuers) scoped to
    /// <paramref name="routeId"/> so the route's <c>chains/server.crt</c> holds the real issuer
    /// bundle rather than a copy of the leaf.
    /// </summary>
    Task PersistSiteCertificateChain(X509Certificate2Collection chain, string? routeId, CancellationToken cancellationToken = default);

    Task PersistAccountCertificate(IKey certificate);

    Task PersistChallenges(ChallengeDto[] challenges);

    Task DeleteChallenges(ChallengeDto[] challenges);

    /// <summary>
    /// Returns the PEM-encoded leaf private key previously persisted for <paramref name="routeId"/>,
    /// or null when no key has been persisted yet. Used by the renewal engine to reuse a route's
    /// private key across renewals so the public key stays stable.
    /// </summary>
    Task<string?> GetPersistedRouteKey(string routeId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Persists the PEM-encoded leaf private key for <paramref name="routeId"/> so that subsequent
    /// renewals of the same route reuse it.
    /// </summary>
    Task PersistRouteKey(string routeId, string keyPem, CancellationToken cancellationToken = default);
}
