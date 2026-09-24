namespace OpenCertServer.Mcp.Tools;

using System.Security.Cryptography;
using Ca.Utils.X509;

/// <summary>
/// Check the status of a certificate using OCSP-style logic.
///
/// Input: serialNumber (string, required), issuerNameHash (string), issuerKeyHash (string)
/// Output: McpOcspCheckResult with certificate status (good/revoked/unknown)
/// </summary>
[McpServerToolType]
public class CheckOcspStatusTool
{
    [McpServerTool(Name = "check_ocsp_status", ReadOnly = true, Idempotent = true, Destructive = false)]
    [Description("Check certificate status using OCSP-style certificate identifier fields.")]
    public static async Task<McpOcspCheckResult> CheckOcspStatus(
        IStoreCertificates store,
        [Description("Certificate serial number (hex string)")] string serialNumber,
        [Description("Issuer name hash (SHA-256, hex string)")] string issuerNameHash,
        [Description("Issuer key hash (SHA-256, hex string)")] string issuerKeyHash,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(serialNumber))
        {
            throw new McpException("serialNumber is required");
        }

        // Validate serial number is valid hex
        if (!IsValidHex(serialNumber))
        {
            throw new McpException("serialNumber must be a valid hex-encoded string");
        }

        if (string.IsNullOrWhiteSpace(issuerNameHash) || string.IsNullOrWhiteSpace(issuerKeyHash))
        {
            throw new McpException("issuerNameHash and issuerKeyHash are required");
        }

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
            throw new McpException("issuerNameHash and issuerKeyHash must be valid hex strings");
        }

        var serialBytes = HexToBytes(serialNumber);
        if (serialBytes == null)
        {
            throw new McpException("Failed to parse serialNumber as hex");
        }

        // Default to SHA-256 for hash algorithm
        var algorithmId = new AlgorithmIdentifier(HashAlgorithmName.SHA256.GetHashAlgorithmOid());
        var certId = new CertId(
            algorithmId,
            nameBytes,
            keyBytes,
            serialBytes
        );

        var (_, status, revokedInfo) = await store.GetCertificateStatus(certId, cancellationToken).ConfigureAwait(false);

        return new McpOcspCheckResult
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
