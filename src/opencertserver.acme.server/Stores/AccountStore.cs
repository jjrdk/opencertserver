namespace OpenCertServer.Acme.Server.Stores;

using Abstractions.Model;
using Abstractions.Model.Exceptions;
using Abstractions.Storage;
using Configuration;
using Microsoft.Extensions.Options;

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
        if (string.IsNullOrWhiteSpace(accountId) || !IdentifierRegex.IsMatch(accountId))
        {
            throw new MalformedRequestException("AccountId does not match expected format.");
        }

        var accountPath = GetPath(accountId);

        var account = await LoadFromPath<Account>(accountPath, cancellationToken);
        return account;
    }

    public async Task SaveAccount(Account setAccount, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (setAccount is null)
        {
            throw new ArgumentNullException(nameof(setAccount));
        }

        var accountPath = GetPath(setAccount.AccountId);
        Directory.CreateDirectory(Path.GetDirectoryName(accountPath)!);

        await using var fileStream = File.Open(accountPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.Read);
        var existingAccount = await LoadFromStream<Account>(fileStream, cancellationToken);
        HandleVersioning(existingAccount, setAccount);

        await ReplaceFileStreamContent(fileStream, setAccount, cancellationToken);
    }
}