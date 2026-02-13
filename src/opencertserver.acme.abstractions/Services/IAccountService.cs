using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;

namespace OpenCertServer.Acme.Abstractions.Services;

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Model;

public interface IAccountService
{
    Task<Account> CreateAccount(
        JsonWebKey jwk,
        IEnumerable<string>? contact = null,
        bool termsOfServiceAgreed = false,
        CancellationToken cancellationToken = default);

    Task<Account?> FindAccount(JsonWebKey jwk, CancellationToken cancellationToken = default);

    Task<Account?> LoadAccount(string accountId, CancellationToken cancellationToken = default);

    Task<Account> FromRequest(AcmeHeader header, CancellationToken cancellationToken = default);
}
