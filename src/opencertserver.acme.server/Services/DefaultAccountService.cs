using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;

namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.Model;
using Abstractions.Model.Exceptions;
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

        await _accountStore.SaveAccount(newAccount, cancellationToken);
        return newAccount;
    }

    public async Task<Account?> FindAccount(JsonWebKey jwk, CancellationToken cancellationToken)
    {
        var account = await CreateAccount(jwk, cancellationToken: cancellationToken);
        return account;
    }

    public async Task<Account> FromRequest(AcmeHeader header, CancellationToken cancellationToken)
    {
        //TODO: Get accountId from Kid?
        var accountId = header.GetAccountId();
        var account = await LoadAccount(accountId, cancellationToken);
        ValidateAccount(account);

        return account!;
    }

    public async Task<Account?> LoadAccount(string accountId, CancellationToken cancellationToken)
    {
        return await _accountStore.LoadAccount(accountId, cancellationToken);
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
