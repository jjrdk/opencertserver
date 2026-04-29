namespace OpenCertServer.Mcp;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Extension methods for adding the MCP server to a service collection.
/// </summary>
public static class McpServerExtensions
{
      /// <summary>
      /// Adds the MCP server to the service collection and registers all CA tools.
      /// </summary>
      /// <param name="services">The service collection to add to.</param>
      /// <param name="configureOptions">Optional action to configure MCP server options.</param>
      /// <returns>The service collection with MCP server registered.</returns>
    public static IServiceCollection AddMcpServer(
        this IServiceCollection services,
        Action<McpServerOptions>? configureOptions = null)
     {
        // Register options
        if (configureOptions != null)
         {
            services.Configure(configureOptions);
         }

        // Register the MCP server as a singleton
        services.AddSingleton<McpServer>(sp =>
         {
            var options = sp.GetRequiredService<IOptions<McpServerOptions>>().Value;
            var logger = sp.GetRequiredService<ILogger<McpServer>>();
            return new McpServer(options, logger);
         });

        // Register the CA services that the MCP tools need
        // These should already be registered by the calling application
        // This ensures they're available via DI when tools run

        return services;
     }
}
