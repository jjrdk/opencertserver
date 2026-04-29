namespace OpenCertServer.Mcp;

using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

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

        var host = builder.Build();

        // Configure MCP server options
        var options = new McpServerOptions();
        host.Configuration
            .GetSection("McpServer")
            .Bind(options);

        // Create and initialize the MCP server
        var logger = host.Services.GetRequiredService<ILogger<McpServer>>();
        var mcpServer = new McpServer(options, logger);

        // Register all tools
        mcpServer.RegisterAll();

        // Initialize with DI services
        await mcpServer.InitializeAsync(host.Services);

        // Wait for cancellation
        var cts = new CancellationTokenSource();
        // Start the server (stdio transport)
        await mcpServer.StartAsync(cts.Token);

        Console.CancelKeyPress += (s, e) =>
        {
            cts.Cancel();
            e.Cancel = true;
        };

        try
        {
            await Task.Delay(Timeout.Infinite, cts.Token);
        }
        catch (TaskCanceledException)
        {
            await mcpServer.StopAsync();
        }
    }
}
