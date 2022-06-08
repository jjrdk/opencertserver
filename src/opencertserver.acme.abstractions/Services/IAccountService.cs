namespace OpenCertServer.Acme.Abstractions.Services
{
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using Model;

    public interface IAccountService
    {
        Task<Account> CreateAccount(
            Jwk jwk,
            IEnumerable<string>? contact = null,
            bool termsOfServiceAgreed = false,
            CancellationToken cancellationToken = default);

        Task<Account?> FindAccount(Jwk jwk, CancellationToken cancellationToken = default);

        Task<Account?> LoadAccount(string accountId, CancellationToken cancellationToken = default);

        Task<Account> FromRequest(CancellationToken cancellationToken = default);
    }
}
