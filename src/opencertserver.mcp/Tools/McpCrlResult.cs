namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// Result from a CRL query tool.
/// </summary>
public class McpCrlResult
{
    public required string Profile { get; set; }
    public string? CrlBytesBase64 { get; set; }
    public required DateTimeOffset LastUpdate { get; set; }
    public required DateTimeOffset NextUpdate { get; set; }

     // New parsed fields
    public int Version { get; set; }
    public string? CrlNumber { get; set; }
    public string? Issuer { get; set; }
    public string? SignatureAlgorithm { get; set; }
    public List<McpRevokedCertEntry> RevokedCertificates { get; set; } = new();
}
