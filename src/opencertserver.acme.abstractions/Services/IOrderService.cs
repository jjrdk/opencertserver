namespace OpenCertServer.Acme.Abstractions.Services;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Model;

/// <summary>
/// Defines a service for managing ACME orders and related operations.
/// </summary>
public interface IOrderService
{
    /// <summary>
    /// Creates a new ACME order.
    /// </summary>
    /// <param name="profile">The certificate profile to use, or null for default.</param>
    /// <param name="account">The account requesting the order.</param>
    /// <param name="identifiers">The identifiers for the order.</param>
    /// <param name="notBefore">The not-before date/time for the certificate, if any.</param>
    /// <param name="notAfter">The not-after date/time for the certificate, if any.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The created order object.</returns>
    Task<Order> CreateOrder(
        string? profile,
        Account account,
        IEnumerable<Identifier> identifiers,
        DateTimeOffset? notBefore,
        DateTimeOffset? notAfter,
        CancellationToken cancellationToken);

    /// <summary>
    /// Gets an existing ACME order for the specified account and order ID.
    /// </summary>
    /// <param name="account">The account that owns the order.</param>
    /// <param name="orderId">The order ID.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The order object, or null if not found.</returns>
    Task<Order?> GetOrderAsync(Account account, string orderId, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the order identifiers associated with the specified account.
    /// </summary>
    /// <param name="account">The account that owns the orders.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The order identifiers for the account.</returns>
    Task<IReadOnlyList<string>> GetOrderIds(Account account, CancellationToken cancellationToken);

    /// <summary>
    /// Processes a CSR for the specified order.
    /// </summary>
    /// <param name="account">The account that owns the order.</param>
    /// <param name="orderId">The order ID.</param>
    /// <param name="csr">The certificate signing request, or null.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The updated order object.</returns>
    Task<Order> ProcessCsr(Account account, string orderId, string? csr, CancellationToken cancellationToken);

    /// <summary>
    /// Gets the issued certificate for the specified order.
    /// </summary>
    /// <param name="account">The account that owns the order.</param>
    /// <param name="orderId">The order ID.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The certificate as a byte array.</returns>
    Task<byte[]> GetCertificate(Account account, string orderId, CancellationToken cancellationToken);

    /// <summary>
    /// Processes a challenge for the specified order, authorization, and challenge IDs.
    /// </summary>
    /// <param name="account">The account that owns the order.</param>
    /// <param name="orderId">The order ID.</param>
    /// <param name="authId">The authorization ID.</param>
    /// <param name="challengeId">The challenge ID.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The processed challenge object, or null if not found.</returns>
    Task<Challenge?> ProcessChallenge(
        Account account,
        string orderId,
        string authId,
        string challengeId,
        CancellationToken cancellationToken);

    /// <summary>
    /// Deactivates an authorization for the specified order.
    /// </summary>
    /// <param name="account">The account that owns the order.</param>
    /// <param name="orderId">The order ID.</param>
    /// <param name="authId">The authorization ID.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The updated authorization object.</returns>
    Task<Authorization> DeactivateAuthorization(
        Account account,
        string orderId,
        string authId,
        CancellationToken cancellationToken);
}
