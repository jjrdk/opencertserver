namespace OpenCertServer.Mcp.Tools;

public class McpRevocationStatusResult
{
    public required string Profile { get; set; }
    public required IReadOnlyList<McpCertStatusCheckResult> Checks { get; set; }
    public required int TotalChecks { get; set; }
}