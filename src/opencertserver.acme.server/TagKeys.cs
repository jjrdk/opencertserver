namespace OpenCertServer.Acme.Server;

/// <summary>
/// Centralised tag (attribute) key constants for all ACME OpenTelemetry measurements.
/// Use these keys when adding dimensions to counters, histograms and spans.
/// </summary>
internal static class TagKeys
{
    /// <summary>ACME challenge type, e.g. "http-01", "dns-01", "tls-alpn-01".</summary>
    internal const string ChallengeType = "acme.challenge.type";

    /// <summary>ACME order identifier type, e.g. "dns".</summary>
    internal const string IdentifierType = "acme.identifier.type";

    /// <summary>
    /// Structured error type; set to the exception class name or ACME error type string
    /// on all failure counter and span recordings.
    /// </summary>
    internal const string ErrorType = "error.type";

    /// <summary>HTTP response status code recorded on non-2xx result paths.</summary>
    internal const string HttpStatusCode = "http.response.status_code";
}

