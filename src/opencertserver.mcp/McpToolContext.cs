namespace OpenCertServer.Mcp;

/// <summary>
/// Context provided to each MCP tool handler.
/// Carries the JSON input parameters and dependency injection access.
/// </summary>
public sealed class McpToolContext : IDisposable
{
    private readonly IServiceScope _scope;

    public McpToolContext(IServiceScope scope, object parameters)
    {
        _scope = scope;
        Parameters = parameters;
    }

        /// <summary>The JSON input parameters as received from the MCP client.</summary>
    public object Parameters { get; }

     /// <summary>
     /// Convenience accessor to get a service from the DI container.
     /// </summary>
    public TService GetService<TService>() where TService : notnull
    {
        return _scope.ServiceProvider.GetRequiredService<TService>();
    }

    public void Dispose()
    {
        _scope.Dispose();
    }
}
