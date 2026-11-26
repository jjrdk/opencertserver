namespace OpenCertServer.Acme.Server.Stores;

using System.Collections.Concurrent;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Storage;
using OpenCertServer.Acme.Server.Configuration;
using Microsoft.Extensions.Options;

/// <summary>
/// File-based store for ACME external account keys.
/// Each key is persisted as a JSON file at <c>{ExternalAccountKeyPath}/{keyId}/key.json</c>.
/// </summary>
public sealed class ExternalAccountKeyStore : StoreBase, IStoreExternalAccountKeys
{
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> KeyLocks = new(StringComparer.Ordinal);

    public ExternalAccountKeyStore(IOptions<FileStoreOptions> options)
        : base(options)
    {
        Directory.CreateDirectory(Options.Value.ExternalAccountKeyPath);
    }

    private string GetPath(string keyId)
        => Path.Combine(Options.Value.ExternalAccountKeyPath, keyId, "key.json");

    /// <inheritdoc />
    public async Task<ExternalAccountKey?> LoadKey(string keyId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(keyId) || !IdentifierRegex().IsMatch(keyId))
        {
            return null;
        }

        return await LoadFromPath<ExternalAccountKey>(GetPath(keyId), cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task SaveKey(ExternalAccountKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(key);

        if (string.IsNullOrWhiteSpace(key.KeyId) || !IdentifierRegex().IsMatch(key.KeyId))
        {
            throw new ArgumentException("KeyId must be a non-empty valid identifier.", nameof(key));
        }
        var keyPath = GetPath(key.KeyId);
        Directory.CreateDirectory(Path.GetDirectoryName(keyPath)!);

        var fileStream = File.Open(keyPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);
        await using var stream = fileStream.ConfigureAwait(false);

        var existingKey = await LoadFromStream<ExternalAccountKey>(fileStream, cancellationToken).ConfigureAwait(false);
        HandleVersioning(existingKey, key);

        await ReplaceFileStreamContent(fileStream, key, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public async Task<ExternalAccountKey?> FindActiveKey(string keyId, CancellationToken cancellationToken)
    {
        var key = await LoadKey(keyId, cancellationToken).ConfigureAwait(false);
        return key?.IsUsed == false ? key : null;
    }

    /// <inheritdoc />
    public async Task<bool> TryConsumeKey(string keyId, string? accountId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(keyId) || !IdentifierRegex().IsMatch(keyId))
        {
            return false;
        }

        var keyPath = GetPath(keyId);
        var gate = KeyLocks.GetOrAdd(keyPath, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(keyPath))
            {
                return false;
            }

            FileStream fileStream;
            for (var attempt = 0; ; attempt++)
            {
                try
                {
                    fileStream = File.Open(keyPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                    break;
                }
                catch (IOException) when (attempt < 50 && File.Exists(keyPath))
                {
                    await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken).ConfigureAwait(false);
                }
            }

            await using var stream = fileStream.ConfigureAwait(false);
            var key = await LoadFromStream<ExternalAccountKey>(fileStream, cancellationToken).ConfigureAwait(false);
            if (key is null || key.IsUsed)
            {
                return false;
            }

            key.MarkUsed(accountId);
            key.Version = DateTimeOffset.UtcNow.Ticks;
            await ReplaceFileStreamContent(fileStream, key, cancellationToken).ConfigureAwait(false);
            await fileStream.FlushAsync(cancellationToken).ConfigureAwait(false);
            return true;
        }
        finally
        {
            gate.Release();
        }
    }
}