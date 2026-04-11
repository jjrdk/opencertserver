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

    /// <inheritdoc />
    public Task<ExternalAccountKey?> LoadKey(string keyId, CancellationToken cancellationToken)
    {
        _ = _keys.TryGetValue(keyId, out var key);
        return Task.FromResult(key);
    }

    /// <inheritdoc />
    public Task SaveKey(ExternalAccountKey key, CancellationToken cancellationToken)
    {
        _keys[key.KeyId] = key;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<ExternalAccountKey?> FindActiveKey(string keyId, CancellationToken cancellationToken)
    {
        _ = _keys.TryGetValue(keyId, out var key);
        ExternalAccountKey? result = key?.IsUsed == false ? key : null;
        return Task.FromResult(result);
    }
}

