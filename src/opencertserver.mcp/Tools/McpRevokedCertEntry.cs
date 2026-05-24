namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// A single revoked certificate entry in a CRL result.
/// </summary>
public class McpRevokedCertEntry
{
     /// <summary>Serial number (hex string).</summary>
    public required string SerialNumber { get; set; }

     /// <summary>When the certificate was revoked (UTC).</summary>
    public DateTimeOffset RevocationTime { get; set; }

     /// <summary>Revocation reason code, if present.</summary>
    public string? Reason { get; set; }

     /// <summary>Optional invalidity date (different from actual revocation time).</summary>
    public DateTimeOffset? InvalidityDate { get; set; }
}
