namespace OpenCertServer.Acme.Server.Stores
{
    using System.Globalization;
    using Abstractions.Model;
    using Abstractions.Storage;
    using Configuration;
    using Microsoft.Extensions.Options;

    public class NonceStore : INonceStore
    {
        private readonly IOptions<FileStoreOptions> _options;

        public NonceStore(IOptions<FileStoreOptions> options)
        {
            _options = options;
            Directory.CreateDirectory(_options.Value.NoncePath);
        }

        public async Task SaveNonceAsync(Nonce nonce, CancellationToken cancellationToken)
        {
            if (nonce is null)
            {
                throw new ArgumentNullException(nameof(nonce));
            }

            var noncePath = Path.Combine(_options.Value.NoncePath, nonce.Token);
            await File.WriteAllTextAsync(noncePath, DateTime.Now.ToString("o", CultureInfo.InvariantCulture), cancellationToken);
        }

        public Task<bool> TryRemoveNonceAsync(Nonce nonce, CancellationToken cancellationToken)
        {
            if (nonce is null)
            {
                throw new ArgumentNullException(nameof(nonce));
            }

            var noncePath = Path.Combine(_options.Value.NoncePath, nonce.Token);
            if (!File.Exists(noncePath))
            {
                return Task.FromResult(false);
            }

            File.Delete(noncePath);
            return Task.FromResult(true);
        }
    }
}
