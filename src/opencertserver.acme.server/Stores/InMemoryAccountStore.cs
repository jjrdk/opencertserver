namespace OpenCertServer.Acme.Server.Stores;

using Abstractions.Model;
using Abstractions.Storage;
using Microsoft.IdentityModel.Tokens;

internal sealed class InMemoryAccountStore : IStoreAccounts
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

    /// <inheritdoc />
    public Task<Account?> FindAccount(JsonWebKey jwk, CancellationToken cancellationToken)
    {
        var thumbprint = Base64UrlEncoder.Encode(jwk.ComputeJwkThumbprint());
        var account = _accounts.Values.FirstOrDefault(x =>
            string.Equals(Base64UrlEncoder.Encode(x.Jwk.ComputeJwkThumbprint()), thumbprint, StringComparison.Ordinal));
        return Task.FromResult(account);
    }
}
