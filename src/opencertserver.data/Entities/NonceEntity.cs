namespace OpenCertServer.Data.Entities;

/// <summary>EF Core entity backing an ACME nonce. The token is the primary key.</summary>
public class NonceEntity
{
    /// <summary>The nonce token, and the primary key.</summary>
    public required string Token { get; set; }

    /// <summary>When the nonce was created (UTC).</summary>
    public DateTimeOffset Created { get; set; }
}