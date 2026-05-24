namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// Metadata about the CA server, returned by the get_server_metadata tool.
/// </summary>
public class McpServerMetadata
{
     /// <summary>Human-readable server name.</summary>
    public required string ServerName { get; set; }

     /// <summary>Semver version string.</summary>
    public required string ServerVersion { get; set; }

     /// <summary>List of CA profiles with their configurations.</summary>
    public required List<CaProfileInfo> CaProfiles { get; set; }

     /// <summary>OCSP responder URLs configured on the CA.</summary>
    public required string[] OcspUrls { get; set; }

     /// <summary>CRL distribution point URLs.</summary>
    public required string[] CrlUrls { get; set; }

     /// <summary>CA Issuers URLs for certificate chain building.</summary>
    public required string[] CaIssuersUrls { get; set; }

     /// <summary>EST protocol endpoints (Relative paths).</summary>
    public required EstEndpoints EstEndpoints { get; set; }

     /// <summary>Supported public key types (RSA, ECDSA).</summary>
    public required string[] SupportedKeyTypes { get; set; }

     /// <summary>Supported signature algorithms.</summary>
    public required string[] SupportedSignatureAlgorithms { get; set; }

     /// <summary>Minimum CSR key size allowed (e.g. 2048 for RSA).</summary>
    public int MinCsrKeySize { get; set; }

     /// <summary>Maximum CSR key size allowed (e.g. 4096 for RSA).</summary>
    public int MaxCsrKeySize { get; set; }

     /// <summary>Current server UTC timestamp (for client coordination).</summary>
    public DateTimeOffset ServerTime { get; set; } = DateTimeOffset.UtcNow;
}
