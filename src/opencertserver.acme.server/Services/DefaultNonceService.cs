namespace OpenCertServer.Acme.Server.Services
{
    using System.Threading;
    using System.Threading.Tasks;
    using Abstractions.Model;
    using Abstractions.Services;
    using Abstractions.Storage;
    using Microsoft.Extensions.Logging;

    public class DefaultNonceService : INonceService
    {
        private readonly INonceStore _nonceStore;
        private readonly ILogger<DefaultNonceService> _logger;

        public DefaultNonceService(INonceStore nonceStore, ILogger<DefaultNonceService> logger)
        {
            _nonceStore = nonceStore;
            _logger = logger;
        }

        public  async Task<Nonce> CreateNonceAsync(CancellationToken cancellationToken)
        {
            var nonce = new Nonce(GuidString.NewValue());

            await _nonceStore.SaveNonceAsync(nonce, cancellationToken);
            _logger.LogInformation($"Created and saved new nonce: {nonce.Token}.");

            return nonce;
        }
    }
}
