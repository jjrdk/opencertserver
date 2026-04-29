namespace OpenCertServer.Mcp;

/// <summary>
/// Describes one MCP tool available on the CA server.
/// Contains the definition used for MCP tool-listing responses.
/// </summary>
public class McpToolDefinition
{
        /// <summary>Tool name as exposed to MCP clients.</summary>
    public required string Name { get; set; }

        /// <summary>Human-readable description of what the tool does.</summary>
    public required string Description { get; set; }

        /// <summary>JSON Schema describing the input parameters for the tool.</summary>
    public string? InputSchema { get; set; }

        /// <summary>
        /// Callback invoked when the tool is called.
        /// </summary>
    public required Func<McpToolContext, Task<McpToolResult>> Handler { get; set; }
}
