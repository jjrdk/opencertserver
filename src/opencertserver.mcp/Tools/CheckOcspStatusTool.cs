namespace OpenCertServer.Mcp.Tools;

using System.Security.Cryptography;
using Ca.Utils.X509;

/// <summary>
/// Check the status of a certificate using OCSP-style logic.
///
/// Input: serialNumber (string, required), issuerNameHash (string), issuerKeyHash (string)
/// Output: McpOcspCheckResult with certificate status (good/revoked/unknown)
/// </summary>
public static class CheckOcspStatusTool
{
    public static async Task<McpToolResult> Handle(McpToolContext context)
    {
        var parameters = context.Parameters as IDictionary<string, object>;

        var serialNumber = parameters?.TryGetValue("serialNumber", out var snObj) ?? false
            ? snObj.ToString()
            : null;

        if (string.IsNullOrWhiteSpace(serialNumber))
        {
            return McpToolResult.Fail("serialNumber is required");
        }

        // Validate serial number is valid hex
        if (!ParameterHelper.IsValidHex(serialNumber))
        {
            return McpToolResult.Fail("serialNumber must be a valid hex-encoded string");
        }

        var issuerNameHash = parameters?.TryGetValue("issuerNameHash", out var inhObj) ?? false
            ? inhObj.ToString()
            : null;

        var issuerKeyHash = parameters?.TryGetValue("issuerKeyHash", out var ikhObj) ?? false
            ? ikhObj.ToString()
            : null;

        if (string.IsNullOrWhiteSpace(issuerNameHash) || string.IsNullOrWhiteSpace(issuerKeyHash))
        {
            return McpToolResult.Fail("issuerNameHash and issuerKeyHash are required");
        }

        var store = context.GetService<IStoreCertificates>();

        // Build CertId from inputs
        byte[] nameBytes = null!;
        byte[] keyBytes = null!;
        try
        {
            nameBytes = Convert.FromHexString(issuerNameHash);
            keyBytes = Convert.FromHexString(issuerKeyHash);
        }
        catch
        {
            return McpToolResult.Fail("issuerNameHash and issuerKeyHash must be valid hex strings");
        }

        var serialBytes = ParameterHelper.HexToBytes(serialNumber);
        if (serialBytes == null)
        {
            return McpToolResult.Fail("Failed to parse serialNumber as hex");
        }

        // Default to SHA-256 for hash algorithm
        var algorithmId = new AlgorithmIdentifier(HashAlgorithmName.SHA256.GetHashAlgorithmOid());
        var certId = new CertId(
            algorithmId,
            nameBytes,
            keyBytes,
            serialBytes
        );

        var (_, status, revokedInfo) = await store.GetCertificateStatus(certId, CancellationToken.None);

        var result = new McpOcspCheckResult
        {
            SerialNumber = serialNumber,
            Status = status switch
            {
                CertificateStatus.Good => McpCertificateStatus.Good,
                CertificateStatus.Revoked => McpCertificateStatus.Revoked,
                _ => McpCertificateStatus.Unknown
            },
            RevocationReason = revokedInfo?.RevocationReason,
            RevocationTime = revokedInfo?.RevocationTime,
            ThisUpdate = DateTimeOffset.UtcNow,
            NextUpdate = DateTimeOffset.UtcNow.AddHours(1)
        };

        return McpToolResult.Ok(result);
    }

    public static McpToolDefinition Create()
    {
        return new McpToolDefinition
        {
            Name = "check_ocsp_status",
            Description =
                "Check the revocation status of a certificate using OCSP-style logic. Requires serial number, issuer name hash (hex), and issuer key hash (hex). Returns good, revoked, or unknown status.",
            InputSchema = """
                          {
                                             "type": "object",
                                             "properties": {
                                                 "serialNumber": {
                                                     "type": "string",
                                                     "description": "Certificate serial number (hex string)"
                                                 },
                                                 "issuerNameHash": {
                                                     "type": "string",
                                                     "description": "Issuer name hash (SHA-256, hex string)"
                                                 },
                                                 "issuerKeyHash": {
                                                     "type": "string",
                                                     "description": "Issuer key hash (SHA-256, hex string)"
                                                 }
                                             },
                                             "required": ["serialNumber", "issuerNameHash", "issuerKeyHash"],
                                             "additionalProperties": false
                                         }
                          """,
            Handler = Handle
        };
    }
}
