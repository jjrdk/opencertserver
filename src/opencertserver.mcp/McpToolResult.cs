namespace OpenCertServer.Mcp;

/// <summary>
/// Result returned by an MCP tool invocation.
/// Wraps success content or an error with a message and code.
/// </summary>
public class McpToolResult
{
     /// <summary>
     /// Whether the tool invocation was successful.
     /// </summary>
    public bool IsSuccess { get; }

    public McpToolResult(bool success, object? content = null, string? errorMessage = null, int errorCode = 0)
     {
        IsSuccess = success;
        Content = content;
        ErrorMessage = errorMessage;
        ErrorCode = errorCode;
     }

     /// <summary>Success content (JSON-serializable). Null when failed.</summary>
    public object? Content { get; }

     /// <summary>Error message when the tool failed.</summary>
    public string? ErrorMessage { get; }

     /// <summary>Error code when the tool failed.</summary>
    public int ErrorCode { get; }

     /// <summary>Create a success result with the given content.</summary>
    public static McpToolResult Ok(object content) => new(true, content);

     /// <summary>Create a failure result with an error message and optional code.</summary>
    public static McpToolResult Fail(string message, int code = 400) => new(false, null, message, code);
}
