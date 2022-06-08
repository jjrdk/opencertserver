namespace OpenCertServer.Acme.Server.Stores;

using Abstractions.Model;
using Abstractions.Storage;

internal class InMemoryAccountStore : IStoreAccounts
{
    private readonly Dictionary<string, Account> _accounts = new();
    /// <inheritdoc />
    public Task SaveAccount(Account account, CancellationToken cancellationToken)
    {
        _accounts[account.AccountId] = account;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<Account?> LoadAccount(string accountId, CancellationToken cancellationToken)
    {
        _ = _accounts.TryGetValue(accountId, out var account);
        return Task.FromResult(account);
    }
}