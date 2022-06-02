namespace OpenCertServer.CertServer.Tests;

using Acme.Abstractions.Model;
using Acme.Abstractions.Storage;

internal class InMemoryAccountStore : IAccountStore
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