using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Storage;
using OpenCertServer.Acme.Server.Configuration;
using Microsoft.Extensions.Options;

namespace OpenCertServer.Acme.Server.Stores;

/// <summary>
/// File-based store for ACME external account keys.
/// Each key is persisted as a JSON file at <c>{ExternalAccountKeyPath}/{keyId}/key.json</c>.
/// </summary>
public sealed class ExternalAccountKeyStore : StoreBase, IStoreExternalAccountKeys
{
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
}

