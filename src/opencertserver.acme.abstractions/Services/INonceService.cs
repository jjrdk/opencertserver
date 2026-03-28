namespace OpenCertServer.Acme.Abstractions.Services;

using System.Threading;
using System.Threading.Tasks;
using Model;

/// <summary>
/// Defines a service for creating and managing ACME nonces.
/// </summary>
public interface INonceService
{
    /// <summary>
    /// Creates a new ACME nonce asynchronously.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The created nonce object.</returns>
    Task<Nonce> CreateNonceAsync(CancellationToken cancellationToken);
}
