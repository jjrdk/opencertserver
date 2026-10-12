namespace OpenCertServer.Mcp.Tests;

using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Mcp.Tests.Support;
using Tools;

/// <summary>
/// Per-scenario shared state for the MCP step definitions.
///
/// Reqnroll resolves binding classes that are constructed for each scenario, and
/// each scenario gets its own binding container -- so this instance is fresh for
/// every scenario and is never shared between concurrently executing tests.
///
/// This replaces the previous static 'TestSharedState' class. Static mutable
/// test state races with xUnit v3, which runs test collections in parallel by
/// default: one scenario could clear or overwrite another scenario's results
/// mid-run, producing intermittent NullReferenceExceptions and false assertion
/// failures. Making the context per-scenario removes the race at its source.
/// </summary>
public sealed class McpScenarioContext
{
    // Result objects set by When-steps, asserted by Then-steps (same scenario).
    public McpCertificateItem? SignedCert { get; set; }

    public McpToolResult? ToolResult { get; set; }

    public McpRevocationStatusResult? RevocationStatusResult { get; set; }

    public McpOcspCheckResult? OcspResult { get; set; }

    public McpCrlResult? CrlResult { get; set; }

    public McpCaCertificatesResult? CaCertsResult { get; set; }

    public McpCertificateSearchResult? SearchResult { get; set; }

    public McpServerMetadata? ServerMetadata { get; set; }

    public IReadOnlyDictionary<string, McpToolDefinition>? Tools { get; set; }

    public IStoreCertificates? Store { get; set; }

    public string? RequestedSerialNumber { get; set; }

    public string? IssuedSerialNumber { get; set; }

    // F-02 authorization-coverage state: the fail-closed CA-operation gate
    // (McpServerConfiguration.EnsureConfigured) is exercised through these fields.
    public OpenCertServer.Mcp.McpServerOptions? McpConfigurationOptions { get; set; }

    public Exception? McpConfigurationError { get; set; }

    public bool McpConfigurationStartupAllowed { get; set; }
}
