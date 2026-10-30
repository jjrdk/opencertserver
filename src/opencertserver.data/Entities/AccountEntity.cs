namespace OpenCertServer.Data.Entities;

/// <summary>
/// EF Core entity backing an ACME account (RFC 8555 §7.3).
///
/// The full <see cref="OpenCertServer.Acme.Abstractions.Model.Account"/> is serialized to the <see cref="Payload"/>
/// column via <c>DataSerializerContext</c> (preserving get-only identity fields), while the scalar columns
/// <see cref="JwkThumbprint"/> and <see cref="ExternalAccountId"/> are indexed for the lookup paths.
/// </summary>
public class AccountEntity
{
    /// <summary>The unique account identifier, and the primary key.</summary>
    public required string AccountId { get; set; }

    /// <summary>Base64 of the account key JWK thumbprint, used by <c>FindAccount</c>.</summary>
    public required string JwkThumbprint { get; set; }

    /// <summary>External account binding this account was created with (RFC 8555 §7.3.4), if any.</summary>
    public string? ExternalAccountId { get; set; }

    /// <summary>The account status, serialized as the enum name.</summary>
    public required string Status { get; set; }

    /// <summary>The full account serialized to JSON.</summary>
    public required string Payload { get; set; }

    /// <summary>Optimistic-concurrency version token.</summary>
    public long Version { get; set; }
}
