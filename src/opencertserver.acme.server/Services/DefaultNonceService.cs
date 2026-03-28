namespace OpenCertServer.Acme.Server.Services;

using System.Threading;
using System.Threading.Tasks;
using Abstractions.Model;
using Abstractions.Services;
using Abstractions.Storage;

public sealed class DefaultNonceService : INonceService
{
    private readonly INonceStore _nonceStore;

    public DefaultNonceService(INonceStore nonceStore)
    {
        _nonceStore = nonceStore;
    }

    public  async Task<Nonce> CreateNonceAsync(CancellationToken cancellationToken)
    {
        var nonce = new Nonce(GuidString.NewValue());

        await _nonceStore.SaveNonceAsync(nonce, cancellationToken).ConfigureAwait(false);

        return nonce;
    }
}
