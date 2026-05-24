using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// Get a specific certificate by serial number.
///
/// Input: serialNumber (string, required), includePem (bool, default false)
/// Output: McpCertificateItem with full certificate metadata, optionally PEM
/// </summary>
public static class GetCertificateTool
{
    private static byte[]? HexToBytes(string hex)
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

    private static string SerialNumberToString(X509Certificate2 cert)
    {
        // Use GetSerialNumberString() which returns big-endian hex matching the store's key format
        return cert.GetSerialNumberString();
    }

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

        var includePem = parameters?.TryGetValue("includePem", out var pemObj) ?? false
            ? ParameterHelper.GetBoolean(pemObj, false)
            : false;

        var store = context.GetService<IStoreCertificates>();

        var serialBytes = ParameterHelper.HexToBytes(serialNumber);
        if (serialBytes == null)
        {
            return McpToolResult.Fail("serialNumber must be a valid hex-encoded string");
        }

        var certs = store.GetCertificatesById(CancellationToken.None, serialBytes);
        var certList = await certs.ToListAsync(CancellationToken.None);

        if (!certList.Any())
        {
            return McpToolResult.Fail($"Certificate with serial number {serialNumber} not found",
                (int)McpErrorCode.CertificateNotFound);
        }

        var cert = certList.First();

        var pem = includePem ? cert.ExportCertificatePem() : null;

        // Look up revocation status from store
        var inventory = await store.GetInventory(0, int.MaxValue, CancellationToken.None)
            .FirstOrDefaultAsync(i => i.SerialNumber.Equals(serialNumber, StringComparison.OrdinalIgnoreCase), CancellationToken.None);

        var result = new McpCertificateItem
        {
            SerialNumber = SerialNumberToString(cert),
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

        return McpToolResult.Ok(result);
    }

    public static McpToolDefinition Create()
    {
        return new McpToolDefinition
        {
            Name = "get_certificate",
            Description =
                "Get a certificate by its serial number. Returns full certificate metadata and optionally the PEM-encoded certificate.",
            InputSchema = """
                          {
                                           "type": "object",
                                           "properties": {
                                               "serialNumber": {
                                                   "type": "string",
                                                   "description": "Certificate serial number (hex string)"
                                               },
                                               "includePem": {
                                                   "type": "boolean",
                                                   "description": "Include PEM-encoded certificate in response",
                                                   "default": false
                                               }
                                           },
                                           "required": ["serialNumber"],
                                           "additionalProperties": false
                                       }
                          """,
            Handler = Handle
        };
    }
}
