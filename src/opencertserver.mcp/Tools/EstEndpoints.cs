namespace OpenCertServer.Mcp.Tools;

public class EstEndpoints
{
    public required string CaBundle { get; set; }
    public required string SimpleEnroll { get; set; }
    public required string SimpleReenroll { get; set; }
    public required string Pkipath { get; set; }
}