namespace OpenCertServer.Mcp.Tools;

using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Check the revocation status of one or more certificates by serial number.
/// More user-friendly than check_ocsp_status because it doesn't require
/// manual hash computation.
///
/// Input: serialNumbers (array of strings, required) - list of serial numbers
///        profileName (string, optional) - CA profile name
/// Output: List of McpCertStatusCheckResult per serial number
/// </summary>
[McpServerToolType]
public class GetRevocationStatusTool
{
    [McpServerTool(Name = "get_revocation_status", ReadOnly = true, Idempotent = true, Destructive = false)]
    [Description("Check revocation status for one or more certificate serial numbers.")]
    public static async Task<McpRevocationStatusResult> GetRevocationStatus(
        IStoreCertificates store,
        [Description("Array of certificate serial numbers (hex strings)")] string[] serialNumbers,
        [Description("CA profile name (optional, uses default if omitted)")] string? profileName = null,
        CancellationToken cancellationToken = default)
    {
        if (serialNumbers.Length == 0)
        {
            throw new McpException("serialNumbers array is required and must not be empty");
        }

        var results = new List<McpCertStatusCheckResult>();

        foreach (var serialNumber in serialNumbers)
        {
            if (string.IsNullOrWhiteSpace(serialNumber))
            {
                continue;
            }

            // Validate hex string before conversion
            if (!IsValidHex(serialNumber))
            {
                throw new McpException($"Invalid hex serial number: {serialNumber}");
            }

            var serialBytes = HexToBytes(serialNumber);
            if (serialBytes == null)
            {
                throw new McpException($"Failed to parse serial number: {serialNumber}");
            }

            // Build CertId with SHA-256 as the default hash algorithm
            var algorithmId = new AlgorithmIdentifier(HashAlgorithmName.SHA256.GetHashAlgorithmOid());
            var certId = new CertId(
                algorithmId,
                Array.Empty<byte>(), // issuer name hash (placeholder - store lookup by serial)
                Array.Empty<byte>(), // issuer key hash
                serialBytes
            );

            var (_, status, revokedInfo) = await store.GetCertificateStatus(certId, cancellationToken).ConfigureAwait(false);

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

        return new McpRevocationStatusResult
        {
            Profile = profileName ?? "(default)",
            Checks = results,
            TotalChecks = results.Count
        };
    }

    private static bool IsValidHex(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        foreach (var c in value)
        {
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            {
                return false;
            }
        }

        return true;
    }

    private static byte[]? HexToBytes(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
        {
            return null;
        }

        if (!IsValidHex(hex))
        {
            return null;
        }

        try
        {
            var normalized = hex.Length % 2 == 0 ? hex : $"0{hex}";
            return Convert.FromHexString(normalized);
        }
        catch
        {
            return null;
        }
    }
}