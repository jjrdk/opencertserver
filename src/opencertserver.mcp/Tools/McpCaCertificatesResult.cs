namespace OpenCertServer.Mcp.Tools;

public class McpCaCertificatesResult
{
    public required string[] Profiles { get; set; }
    public required List<McpCertificateItem> Certificates { get; set; }
    public required int Count { get; set; }
}