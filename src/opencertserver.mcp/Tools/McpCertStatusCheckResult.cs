using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Mcp.Tools;

public class McpCertStatusCheckResult
{
    public required string SerialNumber { get; set; }
    public required McpCertificateStatus Status { get; set; }
    public X509RevocationReason? RevocationReason { get; set; }
    public DateTimeOffset? RevocationTime { get; set; }
    public required bool FoundInStore { get; set; }
}