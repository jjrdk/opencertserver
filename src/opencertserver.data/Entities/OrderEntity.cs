namespace OpenCertServer.Data.Entities;

/// <summary>EF Core entity backing an ACME order (RFC 8555 §7.1.3).</summary>
public class OrderEntity
{
    /// <summary>The unique order identifier, and the primary key.</summary>
    public required string OrderId { get; set; }

    /// <summary>Account that owns this order, indexed for <c>GetOrderIds</c>.</summary>
    public required string AccountId { get; set; }

    /// <summary>The order status, serialized as the enum name.</summary>
    public required string Status { get; set; }

    /// <summary>True when an authorization still holds a <c>Processing</c> challenge; indexed for <c>GetValidatableOrders</c>.</summary>
    public bool HasProcessingChallenge { get; set; }

    /// <summary>The full order serialized to JSON, including its authorization graph.</summary>
    public required string Payload { get; set; }

    /// <summary>Optimistic-concurrency version token.</summary>
    public long Version { get; set; }
}