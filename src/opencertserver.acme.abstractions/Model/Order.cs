namespace OpenCertServer.Acme.Abstractions.Model;

using System;
using System.Collections.Generic;
using System.Linq;

[Serializable]
public sealed class Order : IVersioned
{
    private static readonly Dictionary<OrderStatus, OrderStatus[]> ValidStatusTransitions =
        new()
        {
            { OrderStatus.Pending, [OrderStatus.Ready, OrderStatus.Invalid] },
            { OrderStatus.Ready, [OrderStatus.Processing, OrderStatus.Invalid] },
            { OrderStatus.Processing, [OrderStatus.Valid, OrderStatus.Invalid] }
        };

    public Order(Account account, IEnumerable<Identifier> identifiers)
    {
        OrderId = GuidString.NewValue();
        Status = OrderStatus.Pending;

        AccountId = account.AccountId;

        Identifiers = [..identifiers];
        Authorizations = [];
    }

    public string OrderId { get; }
    public string AccountId { get; }

    public OrderStatus Status { get; private set; }

    public List<Identifier> Identifiers { get; private set; }
    public List<Authorization> Authorizations { get; private set; }

    public DateTimeOffset? NotBefore { get; set; }
    public DateTimeOffset? NotAfter { get; set; }
    public DateTimeOffset? Expires { get; set; }

    public AcmeError? Error { get; set; }

    public string? CertificateSigningRequest { get; set; }
    public byte[]? Certificate { get; set; }


    /// <summary>
    /// Concurrency Token
    /// </summary>
    public long Version { get; set; }

    public Authorization? GetAuthorization(string authId)
        => Authorizations.FirstOrDefault(x => x.AuthorizationId == authId);

    public void SetStatus(OrderStatus nextStatus)
    {
        if (!ValidStatusTransitions.TryGetValue(Status, out var transition))
        {
            throw new InvalidOperationException($"Cannot do challenge status transition from '{Status}'.");
        }

        if (!transition.Contains(nextStatus))
        {
            throw new InvalidOperationException($"Cannot do challenge status transition from '{Status}' to {nextStatus}.");
        }

        Status = nextStatus;
    }

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
