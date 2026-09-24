namespace OpenCertServer.Mcp.Tools;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Revoke a certificate by serial number.
///
/// Input: serialNumber (string, required), reason (string, required, one of: Unspecified, KeyCompromise, CACompromise, AffiliationChanged, Superseded, CessationOfOperation, CertificateHold, RemoveFromCRL, PrivilegeWithdrawn, AACompromise)
/// Output: Success/failure status with message
/// </summary>
[McpServerToolType]
public class RevokeCertificateTool
{
    [McpServerTool(Name = "revoke_certificate", ReadOnly = false, Idempotent = false, Destructive = true)]
    [Description("Revoke a certificate by serial number with a revocation reason.")]
    public static async Task<object> RevokeCertificate(
        ICertificateAuthority ca,
        [Description("Certificate serial number (hex string)")] string serialNumber,
        [Description("Revocation reason")] string reason = "Unspecified",
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(serialNumber))
        {
            throw new McpException("serialNumber is required");
        }

        if (!Enum.TryParse(reason, ignoreCase: true, out X509RevocationReason revocationReason))
        {
            throw new McpException(
                $"Invalid revocation reason: {reason}. Valid values: Unspecified, KeyCompromise, CACompromise, AffiliationChanged, Superseded, CessationOfOperation, CertificateHold, RemoveFromCRL, PrivilegeWithdrawn, AACompromise");
        }

        var result = await ca.RevokeCertificate(serialNumber, revocationReason, cancellationToken).ConfigureAwait(false);

        if (result)
        {
            return new { SerialNumber = serialNumber, Reason = reason, Status = "Revoked" };
        }

        throw new McpException($"Certificate with serial number {serialNumber} not found or revocation failed");
    }
}