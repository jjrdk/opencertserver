namespace OpenCertServer.Mcp;

using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Server;

/// <summary>
/// Entry point for the MCP certificate server (stdio transport).
/// Reads JSON-RPC requests from stdin, writes responses to stdout.
/// </summary>
public static class Program
{
    public static async Task Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);
        var services = builder.Services;

        services.AddLogging(logging =>
        {
            logging.AddConsole();
            logging.SetMinimumLevel(LogLevel.Information);
        });
        builder.Configuration.AddEnvironmentVariables("MCP_");

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

        var host = builder.Build();

        // Configure MCP server options
        var options = new McpServerOptions();
        host.Configuration
            .GetSection("McpServer")
            .Bind(options);

        // Create and initialize the MCP server
        var logger = host.Services.GetRequiredService<ILogger<McpServer>>();
        var loggerFactory = host.Services.GetRequiredService<ILoggerFactory>();
        var mcpServer = new McpServer(options, logger, loggerFactory);

        // Register all tools
        mcpServer.RegisterAll();

        // Initialize with DI services
        await mcpServer.InitializeAsync(host.Services);

        // Wait for cancellation
        using var cts = new CancellationTokenSource();
        ConsoleCancelEventHandler? cancelHandler = (s, e) =>
        {
            cts.Cancel();
            e.Cancel = true;
        };
        Console.CancelKeyPress += cancelHandler;

        var startTask = mcpServer.StartAsync(cts.Token);

        try
        {
            await Task.WhenAny(startTask, Task.Delay(Timeout.Infinite, cts.Token));
        }
        finally
        {
            await mcpServer.StopAsync();
            Console.CancelKeyPress -= cancelHandler;
        }

        // Propagate any server start/transport failures after shutdown.
        await startTask;
    }
}
