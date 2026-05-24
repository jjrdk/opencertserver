namespace OpenCertServer.Mcp.Tools;

public class CaProfileInfo
{
    public required string Name { get; set; }
    public required List<string> CertificateChain { get; set; }
    public bool HasPrivateKey { get; set; }
    public double CertificateValidityDays { get; set; }
    public bool HasOcspSigningKey { get; set; }
    public string OcspFreshnessWindow { get; set; } = string.Empty;
}