namespace OpenCertServer.Data.Entities;

/// <summary>EF Core entity backing an external account key (RFC 8555 §7.3.4). Single-use: once bound, not re-issued.</summary>
public class ExternalAccountKeyEntity
{
    /// <summary>The key identifier issued by the CA, and the primary key.</summary>
    public required string KeyId { get; set; }

    /// <summary>The base64url MAC key, indexed so a consumer can verify the key against the MAC key by key id.</summary>
    public required string MacKey { get; set; }

    /// <summary>The HMAC algorithm, e.g. "HS256".</summary>
    public required string MacAlgorithm { get; set; }

    /// <summary>Whether the key has been consumed by an account creation.</summary>
    public bool IsUsed { get; set; }

    /// <summary>The account this key was bound to, or null when unused. Indexed for lookup.</summary>
    public string? BoundAccountId { get; set; }

    /// <summary>When the key was bound, or null when unused.</summary>
    public DateTimeOffset? BoundAt { get; set; }

    /// <summary>Optimistic-concurrency version token.</summary>
    public long Version { get; set; }
}