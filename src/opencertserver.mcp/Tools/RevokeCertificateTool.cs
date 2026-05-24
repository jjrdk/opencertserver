using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// Revoke a certificate by serial number.
///
/// Input: serialNumber (string, required), reason (string, required, one of: Unspecified, KeyCompromise, CACompromise, AffiliationChanged, Superseded, CessationOfOperation, CertificateHold, RemoveFromCRL, PrivilegeWithdrawn, AACompromise)
/// Output: Success/failure status with message
/// </summary>
public static class RevokeCertificateTool
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

        var reasonStr = parameters?.TryGetValue("reason", out var reasonObj) ?? false
            ? reasonObj.ToString()
            : "Unspecified";

        if (!Enum.TryParse(reasonStr, ignoreCase: true, out X509RevocationReason reason))
        {
            return McpToolResult.Fail(
                $"Invalid revocation reason: {reasonStr}. " +
                "Valid values: Unspecified, KeyCompromise, CACompromise, " +
                "AffiliationChanged, Superseded, CessationOfOperation, " +
                "CertificateHold, RemoveFromCRL, PrivilegeWithdrawn, AACompromise");
        }

        var ca = context.GetService<ICertificateAuthority>();
        var result = await ca.RevokeCertificate(serialNumber, reason, CancellationToken.None);

        if (result)
        {
            return McpToolResult.Ok(new { SerialNumber = serialNumber, Reason = reasonStr, Status = "Revoked" });
        }

        return McpToolResult.Fail($"Certificate with serial number {serialNumber} not found or revocation failed",
            (int)McpErrorCode.CertificateRevocationFailed);
    }

    public static McpToolDefinition Create()
    {
        return new McpToolDefinition
        {
            Name = "revoke_certificate",
            Description =
                "Revoke a certificate by its serial number. Requires serial number and revocation reason. Returns success/failure status.",
            InputSchema = @"{
                  'type': 'object',
                  'properties': {
                      'serialNumber': {
                          'type': 'string',
                          'description': 'Certificate serial number (hex string)'
                      },
                      'reason': {
                          'type': 'string',
                          'description': 'Revocation reason',
                          'enum': [
                              'Unspecified', 'KeyCompromise', 'CACompromise',
                              'AffiliationChanged', 'Superseded',
                              'CessationOfOperation', 'CertificateHold',
                              'RemoveFromCRL', 'PrivilegeWithdrawn',
                              'AACompromise'
                          ]
                      }
                  },
                  'required': ['serialNumber', 'reason'],
                  'additionalProperties': false
              }",
            Handler = Handle
        };
    }
}
