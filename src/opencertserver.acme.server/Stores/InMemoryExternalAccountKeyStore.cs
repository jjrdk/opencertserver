namespace OpenCertServer.Acme.Server.Stores;

using Abstractions.Model;
using Abstractions.Storage;

/// <summary>
/// In-memory store for ACME external account keys.
/// Suitable for testing and single-node deployments.
/// </summary>
internal sealed class InMemoryExternalAccountKeyStore : IStoreExternalAccountKeys
{
    private readonly Dictionary<string, ExternalAccountKey> _keys = new(StringComparer.Ordinal);
    private readonly object _sync = new();

    /// <inheritdoc />
    public Task<ExternalAccountKey?> LoadKey(string keyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            _ = _keys.TryGetValue(keyId, out var key);
            return Task.FromResult(key);
        }
    }

    /// <inheritdoc />
    public Task SaveKey(ExternalAccountKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            _keys[key.KeyId] = key;
        }

        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<ExternalAccountKey?> FindActiveKey(string keyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            _ = _keys.TryGetValue(keyId, out var key);
            return Task.FromResult(key?.IsUsed == false ? key : null);
        }
    }

    /// <inheritdoc />
    public Task<bool> TryConsumeKey(string keyId, string? accountId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            if (!_keys.TryGetValue(keyId, out var key) || key.IsUsed)
            {
                return Task.FromResult(false);
            }

            key.MarkUsed(accountId);
            return Task.FromResult(true);
        }
    }
}
