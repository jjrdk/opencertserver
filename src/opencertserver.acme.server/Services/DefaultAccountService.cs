namespace OpenCertServer.Acme.Server.Services
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using Abstractions.Model;
    using Abstractions.Model.Exceptions;
    using Abstractions.RequestServices;
    using Abstractions.Services;
    using Abstractions.Storage;

    public class DefaultAccountService : IAccountService
    {
        private readonly IAcmeRequestProvider _requestProvider;
        private readonly IAccountStore _accountStore;

        public DefaultAccountService(IAcmeRequestProvider requestProvider, IAccountStore accountStore)
        {
            _requestProvider = requestProvider;
            _accountStore = accountStore;
        }

        public async Task<Account> CreateAccount(
            Jwk jwk,
            IEnumerable<string>? contacts = null,
            bool termsOfServiceAgreed = false,
            CancellationToken cancellationToken = default)
        {
            var newAccount = new Account(jwk, contacts, termsOfServiceAgreed ? DateTimeOffset.UtcNow : null);

            await _accountStore.SaveAccount(newAccount, cancellationToken);
            return newAccount;
        }

        public async Task<Account?> FindAccount(Jwk jwk, CancellationToken cancellationToken)
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
            var account = await LoadAcount(accountId, cancellationToken);
            ValidateAccount(account);

            return account!;
        }

        public async Task<Account?> LoadAcount(string accountId, CancellationToken cancellationToken)
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
}
