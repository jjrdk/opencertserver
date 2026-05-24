using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// Check the revocation status of one or more certificates by serial number.
/// More user-friendly than check_ocsp_status because it doesn't require
/// manual hash computation.
///
/// Input: serialNumbers (array of strings, required) - list of serial numbers
///        profileName (string, optional) - CA profile name
/// Output: List of McpCertStatusCheckResult per serial number
/// </summary>
public static class GetRevocationStatusTool
{
    public static async Task<McpToolResult> Handle(McpToolContext context)
    {
        var parameters = context.Parameters as IDictionary<string, object>;

        var serialNumbersObj = parameters?.TryGetValue("serialNumbers", out var snObj) ?? false
            ? ParameterHelper.GetObjectArray(snObj)
            : null;

        if (serialNumbersObj == null || !serialNumbersObj.Any())
        {
            return McpToolResult.Fail("serialNumbers array is required and must not be empty");
        }

        var profileName = parameters?.TryGetValue("profileName", out var profileObj) ?? false
            ? profileObj.ToString()
            : null;

        var store = context.GetService<IStoreCertificates>();
        var results = new List<McpCertStatusCheckResult>();

        foreach (var snObj2 in serialNumbersObj)
        {
            var serialNumber = snObj2.ToString();
            if (string.IsNullOrWhiteSpace(serialNumber))
            {
                continue;
            }

            // Validate hex string before conversion
            if (!ParameterHelper.IsValidHex(serialNumber))
            {
                return McpToolResult.Fail($"Invalid hex serial number: {serialNumber}");
            }

            var serialBytes = ParameterHelper.HexToBytes(serialNumber);
            if (serialBytes == null)
            {
                return McpToolResult.Fail($"Failed to parse serial number: {serialNumber}");
            }

            // Build CertId with SHA-256 as the default hash algorithm
            var algorithmId = new AlgorithmIdentifier(HashAlgorithmName.SHA256.GetHashAlgorithmOid());
            var certId = new CertId(
                algorithmId,
                Array.Empty<byte>(), // issuer name hash (placeholder - store lookup by serial)
                Array.Empty<byte>(), // issuer key hash
                serialBytes
            );

            var (_, status, revokedInfo) = await store.GetCertificateStatus(certId, CancellationToken.None);

            results.Add(new McpCertStatusCheckResult
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
                FoundInStore = status != CertificateStatus.Unknown
            });
        }

        return McpToolResult.Ok(new McpRevocationStatusResult
        {
            Profile = profileName ?? "(default)",
            Checks = results,
            TotalChecks = results.Count
        });
    }

    public static McpToolDefinition Create()
    {
        return new McpToolDefinition
        {
            Name = "get_revocation_status",
            Description =
                "Check the revocation status of one or more certificates by serial number. Returns good, revoked, or unknown status for each. More convenient than check_ocsp_status as it doesn't require manual hash computation.",
            InputSchema = """
                          {
                                            "type": "object",
                                            "properties": {
                                                "serialNumbers": {
                                                    "type": "array",
                                                    "items": { "type": "string" },
                                                    "description": "Array of certificate serial numbers (hex strings)"
                                                },
                                                "profileName": {
                                                    "type": "string",
                                                    "description": "CA profile name (optional, uses default if omitted)"
                                                }
                                            },
                                            "required": ["serialNumbers"],
                                            "additionalProperties": false
                                        }
                          """,
            Handler = Handle
        };
    }
}
