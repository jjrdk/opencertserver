namespace OpenCertServer.Mcp;

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Ca.Server;
using OpenCertServer.Mcp.Tools;

/// <summary>
/// Entry point for the MCP certificate server (stdio transport).
/// Reads JSON-RPC requests from stdin, writes responses to stdout.
/// </summary>
public static class Program
{
    public static async Task Main(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        var services = builder.Services;

        services.AddLogging(logging =>
        {
            logging.AddConsole(consoleLogOptions =>
            {
                // MCP stdio protocol uses stdout for framing, so logs must be on stderr.
                consoleLogOptions.LogToStandardErrorThreshold = LogLevel.Trace;
            });
            logging.SetMinimumLevel(LogLevel.Information);
        });

        builder.Configuration.AddEnvironmentVariables("MCP_");
        services.Configure<McpServerOptions>(builder.Configuration.GetSection("McpServer"));

        // Register CA services required by MCP tools
        services.AddInMemoryCertificateStore();

        // Configure CA based on environment or use self-signed for testing
        var dn = builder.Configuration.GetValue<string>("CA_DN") ?? "CN=MCP Test CA";
        services.AddSelfSignedCertificateAuthority(
            new X500DistinguishedName(dn.StartsWith("CN=") ? dn : $"CN={dn}"),
            Array.Empty<string>(), // OCSP URLs
            Array.Empty<string>(), // CRL URLs
            Array.Empty<string>(), // CA Issuer URLs
            TimeSpan.FromDays(90));

        services
            .AddMcpServer()
            .WithStdioServerTransport()
            .WithTools<GetServerMetadataTool>()
            .WithTools<ListCertificatesTool>()
            .WithTools<SearchCertificatesTool>()
            .WithTools<GetCertificateTool>()
            .WithTools<GetCaCertificatesTool>()
            .WithTools<SignCertificateTool>()
            .WithTools<RevokeCertificateTool>()
            .WithTools<GetRevocationStatusTool>()
            .WithTools<CheckOcspStatusTool>()
            .WithTools<GetCrlTool>();

        await builder.Build().RunAsync().ConfigureAwait(false);
    }
}
