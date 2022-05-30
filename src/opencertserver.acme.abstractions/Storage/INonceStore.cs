namespace OpenCertServer.Acme.Abstractions.Storage
{
    using System.Threading;
    using System.Threading.Tasks;
    using Model;

    public interface INonceStore
    {
        Task SaveNonceAsync(Nonce nonce, CancellationToken cancellationToken);
        Task<bool> TryRemoveNonceAsync(Nonce nonce, CancellationToken cancellationToken);
    }
}
