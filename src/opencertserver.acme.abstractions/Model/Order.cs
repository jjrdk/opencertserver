using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>
/// Represents an ACME order, which tracks the lifecycle of a certificate request and its associated authorizations.
/// </summary>
public sealed class Order : IVersioned
{
    private static readonly Dictionary<OrderStatus, OrderStatus[]> ValidStatusTransitions =
        new()
        {
            { OrderStatus.Pending, [OrderStatus.Ready, OrderStatus.Invalid] },
            { OrderStatus.Ready, [OrderStatus.Processing, OrderStatus.Invalid] },
            { OrderStatus.Processing, [OrderStatus.Valid, OrderStatus.Invalid] }
        };

    /// <summary>
    /// Initializes a new instance of the <see cref="Order"/> class for the specified account, identifiers, and profile.
    /// </summary>
    /// <param name="account">The account placing the order.</param>
    /// <param name="identifiers">The identifiers for which the certificate is requested.</param>
    /// <param name="profile">The certificate profile requested, or null for default.</param>
    public Order(Account account, IEnumerable<Identifier> identifiers, string? profile)
    {
        OrderId = GuidString.NewValue();
        Status = OrderStatus.Pending;

        AccountId = account.AccountId;

        Identifiers = [..identifiers];
        Authorizations = [];
        Profile = profile;
    }

    /// <summary>
    /// Gets the unique order identifier.
    /// </summary>
    public string OrderId { get; }
    /// <summary>
    /// Gets the account ID associated with this order.
    /// </summary>
    public string AccountId { get; }
    /// <summary>
    /// Gets the current status of the order.
    /// </summary>
    public OrderStatus Status { get; private set; }
    /// <summary>
    /// Gets the list of identifiers for the order.
    /// </summary>
    public List<Identifier> Identifiers { get; private set; }
    /// <summary>
    /// Gets the list of authorizations associated with the order.
    /// </summary>
    public List<Authorization> Authorizations { get; private set; }
    /// <summary>
    /// Gets or sets the not-before date/time for the requested certificate, if any.
    /// </summary>
    public DateTimeOffset? NotBefore { get; set; }
    /// <summary>
    /// Gets or sets the not-after date/time for the requested certificate, if any.
    /// </summary>
    public DateTimeOffset? NotAfter { get; set; }
    /// <summary>
    /// Gets or sets the expiration date/time for the order, if any.
    /// </summary>
    public DateTimeOffset? Expires { get; set; }
    /// <summary>
    /// Gets or sets the error object associated with the order, if any.
    /// </summary>
    public AcmeError? Error { get; set; }
    /// <summary>
    /// Gets or sets the certificate signing request (CSR) for the order, if any.
    /// </summary>
    public string? CertificateSigningRequest { get; set; }
    /// <summary>
    /// Gets or sets the issued certificate as a byte array, if any.
    /// </summary>
    public byte[]? Certificate { get; set; }
    /// <summary>
    /// Gets or sets the certificate profile requested, if any.
    /// </summary>
    public string? Profile { get; set; }
    /// <summary>
    /// Gets or sets the concurrency version token for optimistic concurrency control.
    /// </summary>
    public long Version { get; set; }

    /// <summary>
    /// Gets the authorization with the specified ID, or null if not found.
    /// </summary>
    /// <param name="authId">The authorization identifier.</param>
    /// <returns>The matching <see cref="Authorization"/>, or null if not found.</returns>
    public Authorization? GetAuthorization(string authId)
        => Authorizations.FirstOrDefault(x => x.AuthorizationId == authId);

    /// <summary>
    /// Sets the status of the order, enforcing valid status transitions.
    /// </summary>
    /// <param name="nextStatus">The next status to set.</param>
    /// <exception cref="InvalidOperationException">Thrown if the status transition is not allowed.</exception>
    public void SetStatus(OrderStatus nextStatus)
    {
        if (!ValidStatusTransitions.TryGetValue(Status, out var transition))
        {
            throw new InvalidOperationException($"Cannot do challenge status transition from '{Status}'.");
        }

        if (!transition.Contains(nextStatus))
        {
            throw new InvalidOperationException(
                $"Cannot do challenge status transition from '{Status}' to {nextStatus}.");
        }

        Status = nextStatus;
    }

    /// <summary>
    /// Sets the status of the order based on the statuses of its authorizations.
    /// </summary>
    public void SetStatusFromAuthorizations()
    {
        if (Authorizations.All(a => a.Status == AuthorizationStatus.Valid))
        {
            SetStatus(OrderStatus.Ready);
        }
        else if (Authorizations.Any(a => a.Status.IsInvalid()))
        {
            SetStatus(OrderStatus.Invalid);
        }
    }
}
