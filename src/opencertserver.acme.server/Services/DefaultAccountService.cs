using Microsoft.IdentityModel.Tokens;

namespace OpenCertServer.Acme.Server.Services;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Abstractions.Model;
using Abstractions.Model.Exceptions;
using Abstractions.RequestServices;
using Abstractions.Services;
using Abstractions.Storage;

public sealed class DefaultAccountService : IAccountService
{
    private readonly IAcmeRequestProvider _requestProvider;
    private readonly IStoreAccounts _accountStore;

    public DefaultAccountService(IAcmeRequestProvider requestProvider, IStoreAccounts accountStore)
    {
        _requestProvider = requestProvider;
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

    public async Task<Account> FromRequest(CancellationToken cancellationToken)
    {
        var requestHeader = _requestProvider.GetHeader();

        //if (string.IsNullOrEmpty(requestHeader.Kid))
        //{
        //    throw new MalformedRequestException("Kid header is missing");
        //}

        //TODO: Get accountId from Kid?
        var accountId = requestHeader.GetAccountId();
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
