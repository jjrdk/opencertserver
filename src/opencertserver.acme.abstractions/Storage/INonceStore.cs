namespace OpenCertServer.Acme.Abstractions.Storage;

using System.Threading;
using System.Threading.Tasks;
using Model;

/// <summary>
/// Defines a persistence contract for storing and removing ACME nonces.
/// </summary>
public interface INonceStore
{
    /// <summary>
    /// Saves a nonce to the store asynchronously.
    /// </summary>
    /// <param name="nonce">The nonce to save.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    Task SaveNonceAsync(Nonce nonce, CancellationToken cancellationToken);

    /// <summary>
    /// Attempts to remove a nonce from the store asynchronously.
    /// </summary>
    /// <param name="nonce">The nonce to remove.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>True if the nonce was removed; otherwise, false.</returns>
    Task<bool> TryRemoveNonceAsync(Nonce nonce, CancellationToken cancellationToken);
}
