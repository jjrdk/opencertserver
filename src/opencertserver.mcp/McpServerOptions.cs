namespace OpenCertServer.Mcp;

/// <summary>
/// Configuration options for the MCP (Model Context Protocol) certificate authority server.
/// </summary>
public class McpServerOptions
{
      /// <summary>
      /// Name of the MCP server. Shown to MCP clients for identification.
      /// </summary>
    public string ServerName { get; set; } = "OpenCertServer CA";

      /// <summary>
      /// Version string following semver convention.
      /// </summary>
    public string ServerVersion { get; set; } = "3.1.0";

      /// <summary>
      /// When true, the MCP server lists all available tools and their descriptions.
      /// Defaults to true.
      /// </summary>
    public bool ListToolsOnStart { get; set; } = true;

      /// <summary>
      /// When true, the MCP server enables structured logging and telemetry for tool invocations.
      /// Defaults to true.
      /// </summary>
    public bool EnableTelemetry { get; set; } = true;
}
