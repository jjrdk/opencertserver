using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.Exceptions;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;

namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.Model;
using Abstractions.Services;
using Abstractions.Storage;

public sealed class DefaultAccountService : IAccountService
{
    private readonly IStoreAccounts _accountStore;

    public DefaultAccountService(IStoreAccounts accountStore)
    {
        _accountStore = accountStore;
    }

    public async Task<Account> CreateAccount(
        JsonWebKey jwk,
        IEnumerable<string>? contacts = null,
        bool termsOfServiceAgreed = false,
        CancellationToken cancellationToken = default)
    {
        var newAccount = new Account(jwk, contacts, termsOfServiceAgreed ? DateTimeOffset.UtcNow : null);

        await _accountStore.SaveAccount(newAccount, cancellationToken).ConfigureAwait(false);
        return newAccount;
    }

    public async Task<Account?> FindAccount(JsonWebKey jwk, CancellationToken cancellationToken)
    {
        return await _accountStore.FindAccount(jwk, cancellationToken).ConfigureAwait(false);
    }

    public async Task<Account> UpdateAccount(
        Account account,
        IEnumerable<string>? contact,
        bool termsOfServiceAgreed,
        CancellationToken cancellationToken = default)
    {
        ValidateAccount(account);

        account.UpdateContacts(contact);
        if (termsOfServiceAgreed)
        {
            account.AgreeToTermsOfService();
        }

        await _accountStore.SaveAccount(account, cancellationToken).ConfigureAwait(false);
        return account;
    }

    public async Task<Account> DeactivateAccount(Account account, CancellationToken cancellationToken = default)
    {
        ValidateAccount(account);

        account.Deactivate();
        await _accountStore.SaveAccount(account, cancellationToken).ConfigureAwait(false);
        return account;
    }

    public async Task<Account> ChangeKey(Account account, JsonWebKey newKey, CancellationToken cancellationToken = default)
    {
        ValidateAccount(account);
        ArgumentNullException.ThrowIfNull(newKey);

        var existingAccount = await _accountStore.FindAccount(newKey, cancellationToken).ConfigureAwait(false);
        if (existingAccount != null && !string.Equals(existingAccount.AccountId, account.AccountId, StringComparison.Ordinal))
        {
            throw new MalformedRequestException("The proposed account key is already associated with another ACME account.");
        }

        account.ReplaceKey(newKey);
        await _accountStore.SaveAccount(account, cancellationToken).ConfigureAwait(false);
        return account;
    }

    public async Task<Account> FromRequest(AcmeHeader header, CancellationToken cancellationToken)
    {
        //TODO: Get accountId from Kid?
        var accountId = header.GetAccountId();
        var account = await LoadAccount(accountId, cancellationToken).ConfigureAwait(false);
        ValidateAccount(account);

        return account!;
    }

    public async Task<Account?> LoadAccount(string accountId, CancellationToken cancellationToken)
    {
        return await _accountStore.LoadAccount(accountId, cancellationToken).ConfigureAwait(false);
    }

    private static void ValidateAccount(Account? account)
    {
        if (account == null)
        {
            throw new NotFoundException();
        }

        if (account.Status != AccountStatus.Valid)
        {
            throw new ConflictRequestException(AccountStatus.Valid, account.Status);
        }
    }
}
