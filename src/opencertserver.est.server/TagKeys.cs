namespace OpenCertServer.Est.Server;

/// <summary>
/// Centralised tag (attribute) key constants for all EST OpenTelemetry measurements.
/// Use these keys when adding dimensions to counters, histograms and spans.
/// </summary>
internal static class TagKeys
{
    /// <summary>EST profile name (empty string for the default profile).</summary>
    internal const string Profile = "est.profile";

    /// <summary>
    /// Structured error type; set to the exception class name or a short error code
    /// on all failure counter and span recordings.
    /// </summary>
    internal const string ErrorType = "error.type";

    /// <summary>HTTP response status code recorded on non-2xx result paths.</summary>
    internal const string HttpStatusCode = "http.response.status_code";

    internal const string ProfileName = "est.profile";
}

