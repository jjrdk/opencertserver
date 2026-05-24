#pragma warning disable IL2026
#pragma warning disable IL3050

using Microsoft.Extensions.Logging.Abstractions;

namespace OpenCertServer.Mcp.Transport;

/// <summary>
/// JSON-RPC 2.0 message envelope for the MCP protocol.
/// Per the MCP spec, MCP uses JSON-RPC 2.0 with these main methods:
/// "initialize", "tools/list", "tools/call" and notifications
/// like "notifications/initialized", "notifications/exit".
/// </summary>
internal class JsonRpcResponse
{
    [JsonPropertyName("jsonrpc")]
    public string Jsonrpc { get; set; } = "2.0";
    [JsonPropertyName("id")]
    public JsonElement? Id { get; set; }
    [JsonPropertyName("result")]
    public JsonElement? Result { get; set; }
    [JsonPropertyName("error")]
    public JsonRpcError? ErrorResult { get; set; }

    public static JsonRpcResponse Ok(JsonElement? id, JsonElement result)
        => new() { Id = id, Result = result };

    public static JsonRpcResponse Error(JsonElement? id, int code, string message)
        => new() { Id = id, ErrorResult = new JsonRpcError(code, message) };

    public string Serialize()
    {
        return JsonSerializer.Serialize(this, new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase
        });
    }
}

internal class JsonRpcError
{
    public int Code { get; }
    public string Message { get; }
    public JsonElement? Data { get; }

    public JsonRpcError(int code, string message, JsonElement? data = null)
    {
        Code = code;
        Message = message;
        Data = data;
    }
}

internal class JsonRpcNotification
{
    public string Jsonrpc { get; set; } = "2.0";
    public required string Method { get; set; }
    public JsonElement? Params { get; set; }
}

/// <summary>
/// MCP stdio transport - reads JSON-RPC requests from stdin,
/// dispatches to the McpServer, and writes JSON-RPC responses to stdout.
/// </summary>
internal sealed class McpStdioTransport : IDisposable
{
    private readonly McpServer _server;
    private readonly ILogger<McpStdioTransport> _logger;
    private readonly object _syncGate = new();
    private volatile bool _running;

    public McpStdioTransport(McpServer server, ILogger<McpStdioTransport> logger)
    {
        _server = server;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        _running = true;
        _logger.LogInformation("Starting MCP stdio transport");

        // Send capabilities immediately (MCP spec requirement)
        await SendCapabilities();

        using var reader = Console.In;
        while (_running && !cancellationToken.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync();
            if (line == null)
            {
                _logger.LogInformation("Stdin closed, exiting");
                break;
            }
            if (string.IsNullOrWhiteSpace(line))
                continue;

            try
            {
                await ProcessMessage(line, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to process JSON-RPC message");
                var error = JsonRpcResponse.Error(null, -32603, $"Server error: {ex.Message}");
                WriteResponse(error);
            }
        }
    }

    private Task SendCapabilities()
    {
        using var capDoc = JsonDocument.Parse(@"{
            ""jsonrpc"": ""2.0"",
            ""result"": {
                ""protocolVersion"": ""2024-11-05"",
                ""capabilities"": {
                    ""tools"": { ""listChanged"": false },
                    ""logging"": {},
                    ""prompts"": { ""listChanged"": false }
                },
                ""serverInfo"": {
                    ""name"": ""OpenCertServer"",
                    ""version"": ""3.1.0""
                }
            }
        }");
        var result = capDoc.RootElement.GetProperty("result").Clone();
        var response = JsonRpcResponse.Ok(null, result);
        WriteResponse(response);

        return Task.CompletedTask;
    }

    private async Task ProcessMessage(string raw, CancellationToken cancellationToken)
    {
        var doc = JsonDocument.Parse(raw);
        var root = doc.RootElement;

        if (!root.TryGetProperty("method", out var methodProp))
        {
            _logger.LogWarning("Message missing 'method' field, treating as error");
            var error = JsonRpcResponse.Error(null, -32600, "Invalid request: missing method field");
            WriteResponse(error);
            return;
        }

        var method = methodProp.GetString()!;
        JsonElement? id = root.TryGetProperty("id", out var idProp) ? idProp : null;

        _logger.LogDebug("Received method: {Method}", method);

        switch (method)
        {
            case "initialize":
                await HandleInitialize(id);
                break;

            case "tools/list":
                await HandleToolsList(id);
                break;

            case "tools/call":
                if (root.TryGetProperty("params", out var paramsProp))
                    await HandleToolsCall(paramsProp, id);
                else
                    await HandleToolsCall(JsonDocument.Parse("{}").RootElement, id);
                break;

            case "notifications/initialized":
                _logger.LogDebug("Client initialized");
                break;

            case "notifications/exit":
                _logger.LogInformation("Received exit notification");
                _running = false;
                break;

            case "sampling/createMessage":
                var samplingError = JsonRpcResponse.Error(id, -32601, "Method not supported: sampling");
                WriteResponse(samplingError);
                break;

            case "logging/setLevel":
                _logger.LogDebug("Client set log level: {Level}",
                    root.TryGetProperty("params", out var lp) ? lp.ToString() : "unknown");
                var loggingOk = JsonRpcResponse.Ok(id, JsonDocument.Parse("{}").RootElement);
                WriteResponse(loggingOk);
                break;

            default:
                var methodNotFound = JsonRpcResponse.Error(id, -32601, $"Method not found: {method}");
                WriteResponse(methodNotFound);
                break;
        }
    }

    private Task HandleInitialize(JsonElement? id)
    {
        var response = JsonRpcResponse.Ok(id, JsonDocument.Parse("{}").RootElement);
        WriteResponse(response);

        return Task.CompletedTask;
    }

    private Task HandleToolsList(JsonElement? id)
    {
        try
        {
            var tools = _server.GetTools();
            using var stream = new MemoryStream();
            using var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = false });
            {
                writer.WriteStartArray();
                foreach (var kvp in tools)
                {
                    writer.WriteStartObject();
                    writer.WriteString("name", kvp.Key);
                    writer.WriteString("description", kvp.Value.Description);

                    if (!string.IsNullOrEmpty(kvp.Value.InputSchema))
                    {
                        using var schema = JsonDocument.Parse(kvp.Value.InputSchema!);
                        writer.WritePropertyName("inputSchema");
                        writer.WriteRawValue(schema.RootElement.GetRawText());
                    }
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
                writer.Flush();
            }

            var result = JsonDocument.Parse(stream.ToArray());
            var response = JsonRpcResponse.Ok(id, result.RootElement);
            WriteResponse(response);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error listing tools");
            var error = JsonRpcResponse.Error(id, -32603, $"Failed to list tools: {ex.Message}");
            WriteResponse(error);
        }

        return Task.CompletedTask;
    }

    private async Task HandleToolsCall(JsonElement paramsProp, JsonElement? id)
    {
        if (paramsProp.ValueKind != JsonValueKind.Object ||
            !paramsProp.TryGetProperty("name", out var nameProp) ||
            nameProp.ValueKind != JsonValueKind.String)
        {
            var error = JsonRpcResponse.Error(id, -32602, "tool/call: missing 'name' parameter");
            WriteResponse(error);
            return;
        }

        var name = nameProp.GetString();
        if (string.IsNullOrEmpty(name))
        {
            var error = JsonRpcResponse.Error(id, -32602, "tool/call: missing 'name' parameter");
            WriteResponse(error);
            return;
        }

        JsonElement? args = null;
        if (paramsProp.TryGetProperty("arguments", out var argsProp))
            args = argsProp;

         var parameters = (args != null && args.Value.ValueKind == JsonValueKind.Object)
             ? (JsonSerializer.Deserialize<Dictionary<string, object>>(
                args!.Value.ToString(), new JsonSerializerOptions())
               ?? new Dictionary<string, object>())
             : new Dictionary<string, object>();

        var result = await _server.InvokeTool(name!, parameters!);

        if (result.IsSuccess)
        {
            var json = JsonSerializer.Serialize(result.Content);
            using var doc = JsonDocument.Parse(json);
            var response = JsonRpcResponse.Ok(id, doc.RootElement);
            WriteResponse(response);
        }
        else
        {
            using var dataDoc = JsonDocument.Parse(
                JsonSerializer.Serialize(
                    new { code = result.ErrorCode, message = result.ErrorMessage }));
            var error = JsonRpcResponse.Error(id, result.ErrorCode, result.ErrorMessage!);
            WriteResponse(error);
        }
    }

    private void WriteResponse(JsonRpcResponse response)
    {
        var json = response.Serialize();
        lock (_syncGate)
        {
            try
            {
                Console.Out.Write(json + "\n");
                Console.Out.Flush();
                _logger.LogDebug("Sent JSON-RPC response: {Response}", json);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to write response to stdout");
            }
        }
    }

    public void Dispose()
    {
        _running = false;
    }
}
