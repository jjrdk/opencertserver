namespace OpenCertServer.Mcp.Tests;

using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Mcp;
using OpenCertServer.Mcp.Tools;

/// <summary>
/// Shared mutable state accessible from all step definition classes.
/// Reqnroll creates one instance of each step class per scenario,
/// so we need a shared store for results set by When-step classes
/// that are later asserted by Then-steps in CommonToolsSteps.
/// </summary>
public static class TestSharedState
{
    // Result objects set by When-steps, asserted by Then-steps
    public static McpCertificateItem? SignedCert { get; set; }
    public static McpToolResult? ToolResult { get; set; }
    public static McpRevocationStatusResult? RevocationStatusResult { get; set; }
    public static McpOcspCheckResult? OcspResult { get; set; }
    public static McpCrlResult? CrlResult { get; set; }
    public static McpCaCertificatesResult? CaCertsResult { get; set; }
    public static McpCertificateSearchResult? SearchResult { get; set; }
    public static McpServerMetadata? ServerMetadata { get; set; }
    public static IReadOnlyDictionary<string, McpToolDefinition>? Tools { get; set; }
    public static IStoreCertificates? Store { get; set; }
    public static readonly List<X509Certificate2> IssuedCerts = new();

    /// <summary>
    /// Issues a certificate via the MCP sign_certificate tool.
    /// </summary>
    public static async Task<X509Certificate2?> IssueAsync(
        McpServer mcp, string cn, string profile = "rsa")
    {
        using var rsa = RSA.Create(3072);
        var request = new CertificateRequest(
            new X500DistinguishedName(cn),
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        var pemCsr = request.ToPkcs10Base64();
        
        // We use the MCP tool via the fixture - but we don't have the fixture here.
        // This method is not called directly. Instead, each step class uses
        // _fixture.InvokeMcpToolAsync + signs the result into SharedState.
        // Kept for reference only.
        return null;
    }

    public static void Clear()
    {
        SignedCert = null;
        ToolResult = null;
        RevocationStatusResult = null;
        OcspResult = null;
        CrlResult = null;
        CaCertsResult = null;
        SearchResult = null;
        ServerMetadata = null;
        Tools = null;
        Store = null;
        IssuedCerts.Clear();
    }
}
