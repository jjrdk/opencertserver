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

        // Read the resolved MCP options up-front so the CA surface can be gated before the
        // server starts. This binds the *same* configuration that the running server uses.
        var mcpSection = builder.Configuration.GetSection("McpServer");
        var mcpOptions = new McpServerOptions();
        mcpSection.Bind(mcpOptions);
        services.Configure<McpServerOptions>(mcpSection);

        // Register CA services required by MCP tools. The in-memory store is intentionally the
        // only store available here; it is reserved for tests/development (see F-10).
        services.AddInMemoryCertificateStore();

        // Read-only tools are always available.
        var mcpBuilder = services.AddMcpServer()
            .WithStdioServerTransport()
            .WithTools<GetServerMetadataTool>()
            .WithTools<ListCertificatesTool>()
            .WithTools<SearchCertificatesTool>()
            .WithTools<GetCertificateTool>()
            .WithTools<GetCaCertificatesTool>()
            .WithTools<GetRevocationStatusTool>()
            .WithTools<CheckOcspStatusTool>()
            .WithTools<GetCrlTool>();

        // The CA-mutating tools (sign_certificate, revoke_certificate) are opt-in and
        // fail closed. When CA operations are enabled we validate the security preconditions
        // (an authenticated caller and a real, access-controlled CA key) before starting, and
        // refuse to start otherwise so a bare invocation can never forge or revoke certificates.
        if (McpServerConfiguration.ShouldRegisterCaOperations(mcpOptions))
        {
            McpServerConfiguration.EnsureConfigured(mcpOptions);

            var caller = McpServerConfiguration.BuildAuthenticatedCaller(mcpOptions);
            services.AddSingleton(caller);
            services.AddSingleton<IMcpAuthorization>(new DefaultMcpAuthorization(mcpOptions));

            // The self-signed "MCP Test CA" is dev/test only; EnsureConfigured above has
            // already verified AllowSelfSignedTestCa is explicitly set for the in-memory store.
            var dn = builder.Configuration.GetValue<string>("CA_DN") ?? "CN=MCP Test CA";
            services.AddSelfSignedCertificateAuthority(
                new X500DistinguishedName(dn.StartsWith("CN=") ? dn : $"CN={dn}"),
                Array.Empty<string>(), // OCSP URLs
                Array.Empty<string>(), // CRL URLs
                Array.Empty<string>(), // CA Issuer URLs
                TimeSpan.FromDays(90));

            mcpBuilder
                .WithTools<SignCertificateTool>()
                .WithTools<RevokeCertificateTool>();
        }

        await builder.Build().RunAsync().ConfigureAwait(false);
    }
}
