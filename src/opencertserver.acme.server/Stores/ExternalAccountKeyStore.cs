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
    private static readonly ConcurrentDictionary<string, SemaphoreSlim> KeyLocks =
        new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

    public ExternalAccountKeyStore(IOptions<FileStoreOptions> options)
        : base(options)
    {
        Directory.CreateDirectory(Options.Value.ExternalAccountKeyPath);
    }

    private string GetPath(string keyId)
        => Path.GetFullPath(Path.Combine(Options.Value.ExternalAccountKeyPath, keyId, "key.json"));

    private static async Task<FileStream> OpenWithRetry(
        string path, FileMode mode, FileAccess access, FileShare share, CancellationToken cancellationToken)
    {
        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return File.Open(path, mode, access, share);
            }
            catch (IOException ex) when (attempt < 50 && IsSharingConflict(ex))
            {
                await Task.Delay(TimeSpan.FromMilliseconds(10), cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static bool IsSharingConflict(IOException exception)
    {
        // Unix FileStream maps flock's EWOULDBLOCK to IOException with the native errno as HResult.
        if (OperatingSystem.IsWindows())
        {
            return exception.HResult is unchecked((int)0x80070020) or unchecked((int)0x80070021);
        }

        return OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD()
            ? exception.HResult == 35
            : OperatingSystem.IsLinux() && exception.HResult == 11;
    }

    /// <inheritdoc />
    public async Task<ExternalAccountKey?> LoadKey(string keyId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(keyId) || !IdentifierRegex().IsMatch(keyId))
        {
            return null;
        }

        var keyPath = GetPath(keyId);
        var gate = KeyLocks.GetOrAdd(keyPath, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!File.Exists(keyPath))
            {
                return null;
            }

            await using var fileStream = await OpenWithRetry(
                keyPath, FileMode.Open, FileAccess.Read, FileShare.Read, cancellationToken).ConfigureAwait(false);
            return await LoadFromStream<ExternalAccountKey>(fileStream, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            gate.Release();
        }
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
        var gate = KeyLocks.GetOrAdd(keyPath, static _ => new SemaphoreSlim(1, 1));
        await gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(keyPath)!);
            await using var fileStream = await OpenWithRetry(
                keyPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, cancellationToken).ConfigureAwait(false);
            var existingKey = await LoadFromStream<ExternalAccountKey>(fileStream, cancellationToken).ConfigureAwait(false);
            HandleVersioning(existingKey, key);
            await ReplaceFileStreamContent(fileStream, key, cancellationToken).ConfigureAwait(false);
            await fileStream.FlushAsync(cancellationToken).ConfigureAwait(false);
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

            await using var fileStream = await OpenWithRetry(
                keyPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None, cancellationToken).ConfigureAwait(false);
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