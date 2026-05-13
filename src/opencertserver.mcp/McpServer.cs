namespace OpenCertServer.Mcp;

using System.Collections.Concurrent;
using System.Diagnostics;
using OpenCertServer.Mcp.Transport;

/// <summary>
/// The MCP server that hosts certificate authority tools.
/// Implements the Model Context Protocol tool protocol over JSON-RPC 2.0.
/// </summary>
public sealed class McpServer : IDisposable
{
    private readonly McpServerOptions _options;
    private readonly ILogger<McpServer> _logger;
    private readonly ConcurrentDictionary<string, McpToolDefinition> _tools = new();
    private volatile bool _isRunning;
    private IServiceProvider? _serviceProvider;
    private McpStdioTransport? _stdioTransport;

    /// <summary>
    /// Creates a new MCP server instance.
    /// </summary>
    public McpServer(McpServerOptions options, ILogger<McpServer> logger)
    {
        _options = options;
        _logger = logger;
    }

    /// <summary>
    /// Registers a tool with the MCP server.
    /// </summary>
    public void RegisterTool(McpToolDefinition tool)
    {
        if (string.IsNullOrWhiteSpace(tool.Name))
        {
            throw new ArgumentException("Tool name cannot be empty.", nameof(tool));
        }

        if (tool.Handler == null)
        {
            throw new ArgumentNullException(nameof(tool.Handler));
        }

        _tools[tool.Name] = tool;
        _logger.LogDebug("Registered MCP tool: {ToolName}", tool.Name);
    }

    /// <summary>
    /// Gets all registered tool definitions (for MCP tools/list).
    /// </summary>
    public IReadOnlyDictionary<string, McpToolDefinition> GetTools()
    {
        return new Dictionary<string, McpToolDefinition>(_tools);
    }

    /// <summary>
    /// Invokes a tool by name with the given parameters.
    /// Returns success result with output or failure result with error message.
    /// </summary>
    public async Task<McpToolResult> InvokeTool(string toolName, object parameters)
    {
        if (!_tools.TryGetValue(toolName, out var tool))
        {
            return McpToolResult.Fail($"Tool not found: {toolName}", (int)McpErrorCode.ToolNotFound);
        }

        var sw = Stopwatch.GetTimestamp();
        try
        {
            if (_serviceProvider == null)
            {
                return McpToolResult.Fail("Server not initialized. Call InitializeAsync() first.", (int)McpErrorCode.InternalError);
            }

            using var scope = _serviceProvider.CreateScope();
            var context = new McpToolContext(scope, parameters);
            var result = await tool.Handler(context);

            var duration = Stopwatch.GetElapsedTime(sw).TotalSeconds;
            if (result.IsSuccess)
            {
                McpInstruments.RecordSuccess(toolName, duration);
            }
            else
            {
                McpInstruments.RecordFailure(toolName, duration, result.ErrorMessage);
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error invoking tool: {ToolName}", toolName);
            McpInstruments.RecordFailure(toolName, Stopwatch.GetElapsedTime(sw).TotalSeconds, ex.Message);
            return McpToolResult.Fail(ex.Message, (int)McpErrorCode.InternalError);
        }
    }

    /// <summary>
    /// Starts the MCP server (for stdio transport).
    /// </summary>
    public async Task StartAsync(CancellationToken cancellationToken = default)
     {
         _isRunning = true;
         _logger.LogInformation("MCP server starting: {ServerName} v{Version}",
             _options.ServerName, _options.ServerVersion);

        if (_options.ListToolsOnStart)
         {
             _logger.LogInformation("Registered {ToolCount} MCP tool(s)", _tools.Count);
         }

         // Create and start the stdio transport
        var transportLogger = _logger as ILogger<McpStdioTransport>;
        _stdioTransport = new McpStdioTransport(this, transportLogger ?? _logger as ILogger<McpStdioTransport> ?? NullLogger<McpStdioTransport>.Instance);
         await _stdioTransport.StartAsync(cancellationToken);
     }

     /// <summary>
    /// Sets up the stdio transport for future calls to StartAsync.
    /// </summary>
    public void UseStdioTransport()
     {
         // Already handled in StartAsync, this method exists for API compatibility.
    }

    /// <summary>
    /// Stops the MCP server gracefully.
    /// </summary>
    public async Task StopAsync(CancellationToken cancellationToken = default)
    {
        _isRunning = false;
        _logger.LogInformation("MCP server stopping");
        await Task.CompletedTask;
    }

    /// <summary>
    /// Checks if the server is running.
    /// </summary>
    public bool IsRunning => _isRunning;

    /// <summary>
    /// Initializes the server with a service provider, enabling tool execution.
    /// </summary>
    public async Task InitializeAsync(IServiceProvider services, CancellationToken cancellationToken = default)
    {
        _serviceProvider = services;
        _logger.LogInformation("MCP server initialized with {ToolCount} tool(s)", _tools.Count);
        await Task.CompletedTask;
    }

    public void Dispose()
     {
         _isRunning = false;
         _stdioTransport?.Dispose();
         _tools.Clear();
         _serviceProvider = null;
     }
}
