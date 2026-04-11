namespace OpenCertServer.Acme.Abstractions.Storage;

using System.Threading;
using System.Threading.Tasks;
using Model;

/// <summary>
/// Defines a persistence contract for storing and loading ACME external account keys (RFC 8555 §7.3.4).
/// </summary>
public interface IStoreExternalAccountKeys
{
    /// <summary>
    /// Loads an external account key by its key identifier.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The external account key, or null if not found.</returns>
    Task<ExternalAccountKey?> LoadKey(string keyId, CancellationToken cancellationToken);

    /// <summary>
    /// Saves an external account key to the store.
    /// </summary>
    /// <param name="key">The key to save.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    Task SaveKey(ExternalAccountKey key, CancellationToken cancellationToken);

    /// <summary>
    /// Finds an active (unused) external account key by its key identifier.
    /// Returns null when the key does not exist or has already been consumed.
    /// </summary>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The active external account key, or null.</returns>
    Task<ExternalAccountKey?> FindActiveKey(string keyId, CancellationToken cancellationToken);
}

