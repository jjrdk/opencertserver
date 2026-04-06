using OpenCertServer.Acme.Abstractions.Exceptions;

namespace OpenCertServer.Acme.Server.Stores;

using Abstractions.Model;
using Abstractions.Storage;
using Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

public sealed class AccountStore : StoreBase, IStoreAccounts
{
    public AccountStore(IOptions<FileStoreOptions> options)
        : base(options)
    {
        Directory.CreateDirectory(Options.Value.AccountPath);
    }

    private string GetPath(string accountId)
        => Path.Combine(Options.Value.AccountPath, accountId, "account.json");

    public async Task<Account?> LoadAccount(string accountId, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(accountId) || !IdentifierRegex().IsMatch(accountId))
        {
            throw new MalformedRequestException("AccountId does not match expected format.");
        }

        var accountPath = GetPath(accountId);

        var account = await LoadFromPath<Account>(accountPath, cancellationToken).ConfigureAwait(false);
        return account;
    }

    public async Task SaveAccount(Account setAccount, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        ArgumentNullException.ThrowIfNull(setAccount);

        var accountPath = GetPath(setAccount.AccountId);
        Directory.CreateDirectory(Path.GetDirectoryName(accountPath)!);

        var fileStream = File.Open(accountPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);
        await using var stream = fileStream.ConfigureAwait(false);
        var existingAccount = await LoadFromStream<Account>(fileStream, cancellationToken).ConfigureAwait(false);
        HandleVersioning(existingAccount, setAccount);

        await ReplaceFileStreamContent(fileStream, setAccount, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Account?> FindAccount(JsonWebKey jwk, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(jwk);

        var expectedThumbprint = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
        if (!Directory.Exists(Options.Value.AccountPath))
        {
            return null;
        }

        foreach (var accountFilePath in Directory.EnumerateFiles(Options.Value.AccountPath, "account.json",
                     SearchOption.AllDirectories))
        {
            cancellationToken.ThrowIfCancellationRequested();

            var account = await LoadFromPath<Account>(accountFilePath, cancellationToken).ConfigureAwait(false);
            if (account == null)
            {
                continue;
            }

            var currentThumbprint = Base64UrlEncoder.Encode(account.Jwk.ComputeJwkThumbprint());
            if (string.Equals(currentThumbprint, expectedThumbprint, StringComparison.Ordinal))
            {
                return account;
            }
        }

        return null;
    }
}
