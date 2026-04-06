using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;

namespace OpenCertServer.Acme.Abstractions.Services;

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Model;

/// <summary>
/// Defines a service for managing ACME accounts.
/// </summary>
public interface IAccountService
{
    /// <summary>
    /// Creates a new ACME account.
    /// </summary>
    /// <param name="jwk">The JSON Web Key for the account.</param>
    /// <param name="contact">The contact URIs for the account.</param>
    /// <param name="termsOfServiceAgreed">Whether the terms of service have been agreed to.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The created account object.</returns>
    Task<Account> CreateAccount(
        JsonWebKey jwk,
        IEnumerable<string>? contact = null,
        bool termsOfServiceAgreed = false,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Finds an account by its JSON Web Key.
    /// </summary>
    /// <param name="jwk">The JSON Web Key.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The account object, or null if not found.</returns>
    Task<Account?> FindAccount(JsonWebKey jwk, CancellationToken cancellationToken = default);

    /// <summary>
    /// Updates an existing ACME account.
    /// </summary>
    /// <param name="account">The account to update.</param>
    /// <param name="contact">The replacement contact URIs.</param>
    /// <param name="termsOfServiceAgreed">Whether the account agrees to the terms of service.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The updated account object.</returns>
    Task<Account> UpdateAccount(
        Account account,
        IEnumerable<string>? contact,
        bool termsOfServiceAgreed,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Deactivates an existing ACME account.
    /// </summary>
    /// <param name="account">The account to deactivate.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The deactivated account object.</returns>
    Task<Account> DeactivateAccount(Account account, CancellationToken cancellationToken = default);

    /// <summary>
    /// Loads an account by its account ID.
    /// </summary>
    /// <param name="accountId">The account ID.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The account object, or null if not found.</returns>
    Task<Account?> LoadAccount(string accountId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Loads or creates an account from an ACME request header.
    /// </summary>
    /// <param name="header">The ACME request header.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The account object.</returns>
    Task<Account> FromRequest(AcmeHeader header, CancellationToken cancellationToken = default);
}
