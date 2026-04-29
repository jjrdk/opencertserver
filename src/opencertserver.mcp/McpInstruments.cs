using System.Diagnostics;

namespace OpenCertServer.Mcp;

using System.Diagnostics.Metrics;

/// <summary>
/// OpenTelemetry instrumentation helpers for the MCP server.
/// </summary>
internal static class McpInstruments
{
    public static readonly ActivitySource ActivitySource = new("opencertserver.mcp");
    private static readonly Meter Meter = new Meter("opencertserver.mcp", "1.0.0");

    private static readonly Counter<long> TotalRequests =
        Meter.CreateCounter<long>("mcp_tool_requests_total", "Total MCP tool invocations");

    private static readonly Counter<long> ToolSuccesses =
        Meter.CreateCounter<long>("mcp_tool_successes_total", "Successful MCP tool invocations");

    private static readonly Counter<long> ToolFailures =
        Meter.CreateCounter<long>("mcp_tool_failures_total", "Failed MCP tool invocations");

    private static readonly Histogram<double> ToolDuration =
        Meter.CreateHistogram<double>("mcp_tool_duration_seconds", "Duration of MCP tool invocations in seconds");

    /// <summary>Record a successful tool invocation.</summary>
    public static void RecordSuccess(string toolName, double durationSeconds)
    {
        using var activity = ActivitySource.StartActivity($"mcp.tool.{toolName}");
        activity?.AddTag(TagKeys.ToolName, toolName);
        activity?.AddTag(TagKeys.Outcome, "success");
        TotalRequests.Add(1, KeyValuePair.Create<string, object?>("mcp.tool_name", toolName));
        ToolSuccesses.Add(1, KeyValuePair.Create<string, object?>("mcp.tool_name", toolName));
        ToolDuration.Record(durationSeconds, KeyValuePair.Create<string, object?>("mcp.tool_name", toolName));
    }

    /// <summary>Record a failed tool invocation.</summary>
    public static void RecordFailure(string toolName, double durationSeconds, string? error = null)
    {
        using var activity = ActivitySource.StartActivity($"mcp.tool.{toolName}");
        activity?.AddTag(TagKeys.ToolName, toolName);
        activity?.AddTag(TagKeys.Outcome, "failure");
        if (error != null)
        {
            activity?.AddTag("mcp.error", error);
        }

        TotalRequests.Add(1, KeyValuePair.Create<string, object?>("mcp.tool_name", toolName));
        ToolFailures.Add(1, KeyValuePair.Create<string, object?>("mcp.tool_name", toolName));
        ToolDuration.Record(durationSeconds, KeyValuePair.Create<string, object?>("mcp.tool_name", toolName));
    }

    /// <summary>Tag keys used across all MCP metrics.</summary>
    public static class TagKeys
    {
        public const string ToolName = "mcp.tool_name";
        public const string Outcome = "mcp.outcome";
    }
}
