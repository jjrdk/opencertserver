namespace OpenCertServer.Acme.Abstractions.Services
{
    using System.Threading;
    using System.Threading.Tasks;
    using Model;

    public interface INonceService
    {
        Task<Nonce> CreateNonceAsync(CancellationToken cancellationToken);

    }
}
