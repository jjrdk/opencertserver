namespace OpenCertServer.Mcp.Tools;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Get a specific certificate by serial number.
///
/// Input: serialNumber (string, required), includePem (bool, default false)
/// Output: McpCertificateItem with full certificate metadata, optionally PEM
/// </summary>
[McpServerToolType]
public class GetCertificateTool
{
    [McpServerTool(Name = "get_certificate", ReadOnly = true, Idempotent = true, Destructive = false)]
    [Description("Get a certificate by serial number with optional PEM output.")]
    public static async Task<McpCertificateItem> GetCertificate(
        IStoreCertificates store,
        [Description("Certificate serial number (hex string)")] string serialNumber,
        [Description("Include PEM-encoded certificate in response")] bool includePem = false,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(serialNumber))
        {
            throw new McpException("serialNumber is required");
        }

        var serialBytes = ParseHex(serialNumber);
        if (serialBytes == null)
        {
            throw new McpException("serialNumber must be a valid hex-encoded string");
        }

        var certs = store.GetCertificatesById(cancellationToken, serialBytes);
        var certList = await certs.ToListAsync(cancellationToken).ConfigureAwait(false);

        if (!certList.Any())
        {
            throw new McpException($"Certificate with serial number {serialNumber} not found");
        }

        var cert = certList.First();

        var pem = includePem ? cert.ExportCertificatePem() : null;

        // Look up revocation status from store
        var inventory = await store.GetInventory(0, int.MaxValue, cancellationToken)
            .FirstOrDefaultAsync(i => i.SerialNumber.Equals(serialNumber, StringComparison.OrdinalIgnoreCase), cancellationToken).ConfigureAwait(false);

        return new McpCertificateItem
        {
            SerialNumber = cert.GetSerialNumberString(),
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            Thumbprint = cert.Thumbprint,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            PublicKeyAlgorithm = cert.PublicKey?.Oid?.Value ?? "unknown",
            PublicKeySize = ((AsymmetricAlgorithm?)cert.GetRSAPublicKey() ?? cert.GetECDsaPublicKey())?.KeySize ?? 0,
            IsRevoked = inventory?.IsRevoked ?? false,
            RevocationReason = inventory?.RevocationReason,
            RevocationDate = inventory?.RevocationDate,
            Pem = pem
        };
    }

    private static byte[]? ParseHex(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex) || hex.Length % 2 != 0)
        {
            return null;
        }

        try
        {
            return Convert.FromHexString(hex);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}