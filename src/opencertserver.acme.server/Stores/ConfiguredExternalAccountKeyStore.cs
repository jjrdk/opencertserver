namespace OpenCertServer.Acme.Server.Stores;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Storage;

/// <summary>
/// Stores externally provisioned keys in memory and persists only their consumed state.
/// </summary>
public sealed class ConfiguredExternalAccountKeyStore : IStoreExternalAccountKeys
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> KeyLocks =
        new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

    private readonly IReadOnlyDictionary<string, ExternalAccountKey> _keys;
    private readonly string _consumedKeyPath;

    /// <summary>
    /// Initializes a store with externally provisioned keys and a directory for consumption markers.
    /// </summary>
    /// <param name="keys">The configured HMAC keys, kept in memory.</param>
    /// <param name="consumedKeyPath">The directory in which consumed-key metadata is persisted.</param>
    public ConfiguredExternalAccountKeyStore(IEnumerable<ExternalAccountKey> keys, string consumedKeyPath)
    {
        ArgumentNullException.ThrowIfNull(keys);
        ArgumentException.ThrowIfNullOrWhiteSpace(consumedKeyPath);

        _keys = keys.ToDictionary(key => key.KeyId, StringComparer.Ordinal);
        _consumedKeyPath = Path.GetFullPath(consumedKeyPath);
        Directory.CreateDirectory(_consumedKeyPath);
    }

    /// <inheritdoc />
    public Task<ExternalAccountKey?> LoadKey(string keyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_keys.TryGetValue(keyId, out var key))
        {
            return Task.FromResult<ExternalAccountKey?>(null);
        }

        if (!key.IsUsed && LoadConsumedMetadata(key.KeyId) is { } metadata)
        {
            key.MarkUsed(metadata.BoundAccountId, metadata.BoundAt);
        }

        return Task.FromResult<ExternalAccountKey?>(key);
    }

    /// <inheritdoc />
    public async Task SaveKey(ExternalAccountKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(key);
        if (!key.IsUsed)
        {
            return;
        }

        if (!_keys.TryGetValue(key.KeyId, out var configuredKey) || !ReferenceEquals(key, configuredKey))
        {
            throw new InvalidOperationException("Only configured external account keys can be consumed.");
        }

        var markerPath = GetMarkerPath(key.KeyId);
        var gate = KeyLocks.GetOrAdd(markerPath, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await SaveConsumedMetadata(
                    key.KeyId,
                    key.BoundAccountId,
                    key.BoundAt!.Value,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
    }

    /// <inheritdoc />
    public async Task<ExternalAccountKey?> FindActiveKey(string keyId, CancellationToken cancellationToken)
    {
        var key = await LoadKey(keyId, cancellationToken).ConfigureAwait(false);
        return key is { IsUsed: false } ? key : null;
    }

    /// <inheritdoc />
    public async Task<bool> TryConsumeKey(string keyId, string? accountId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_keys.TryGetValue(keyId, out var key))
        {
            return false;
        }

        var markerPath = GetMarkerPath(keyId);
        var gate = KeyLocks.GetOrAdd(markerPath, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (LoadConsumedMetadata(keyId) is { } existingMetadata)
            {
                key.MarkUsed(existingMetadata.BoundAccountId, existingMetadata.BoundAt);
                return false;
            }

            if (key.IsUsed)
            {
                return false;
            }

            var boundAt = DateTimeOffset.UtcNow;
            if (!await SaveConsumedMetadata(keyId, accountId, boundAt, cancellationToken).ConfigureAwait(false))
            {
                if (LoadConsumedMetadata(keyId) is { } consumedMetadata)
                {
                    key.MarkUsed(consumedMetadata.BoundAccountId, consumedMetadata.BoundAt);
                }

                return false;
            }

            key.MarkUsed(accountId, boundAt);
            return true;
        }
        finally
        {
            gate.Release();
        }
    }

    private async Task<bool> SaveConsumedMetadata(
        string keyId,
        string? accountId,
        DateTimeOffset boundAt,
        CancellationToken cancellationToken)
    {
        var markerPath = GetMarkerPath(keyId);
        var temporaryPath = $"{markerPath}.tmp-{Guid.NewGuid():N}";
        try
        {
            await using (var marker = new FileStream(
                             temporaryPath, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                var metadata = new ConsumedKeyMetadata(accountId, boundAt);
                using (var writer = new Utf8JsonWriter(marker))
                {
                    writer.WriteStartObject();
                    writer.WriteString(nameof(metadata.BoundAccountId), metadata.BoundAccountId);
                    writer.WriteString(nameof(metadata.BoundAt), metadata.BoundAt);
                    writer.WriteEndObject();
                    await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
                }

                await marker.FlushAsync(cancellationToken).ConfigureAwait(false);
            }

            try
            {
                File.Move(temporaryPath, markerPath);
                return true;
            }
            catch (IOException) when (LoadConsumedMetadata(keyId) is not null)
            {
                return false;
            }
        }
        finally
        {
            File.Delete(temporaryPath);
        }
    }

    private ConsumedKeyMetadata? LoadConsumedMetadata(string keyId)
    {
        try
        {
            using var stream = File.OpenRead(GetMarkerPath(keyId));
            using var marker = JsonDocument.Parse(stream);
            var root = marker.RootElement;
            var accountIdElement = root.GetProperty(nameof(ConsumedKeyMetadata.BoundAccountId));
            var accountId = accountIdElement.ValueKind == JsonValueKind.Null
                ? null
                : accountIdElement.GetString();
            var boundAt = root.GetProperty(nameof(ConsumedKeyMetadata.BoundAt)).GetDateTimeOffset();
            return new ConsumedKeyMetadata(accountId, boundAt);
        }
        catch (FileNotFoundException)
        {
            return null;
        }
    }

    private string GetMarkerPath(string keyId)
    {
        var name = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(keyId)));
        return Path.Combine(_consumedKeyPath, name + ".used");
    }

    private sealed record ConsumedKeyMetadata(string? BoundAccountId, DateTimeOffset BoundAt);
}
