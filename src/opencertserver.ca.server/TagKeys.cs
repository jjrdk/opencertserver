namespace OpenCertServer.Ca.Server;

/// <summary>
/// Centralised tag (attribute) key constants for all CA/OCSP/CRL OpenTelemetry measurements.
/// Use these keys when adding dimensions to counters, histograms and spans.
/// </summary>
internal static class TagKeys
{
    /// <summary>CA profile name (empty string for the default profile).</summary>
    internal const string Profile = "ca.profile";

    /// <summary>OCSP response status, e.g. "good", "revoked", "unknown".</summary>
    internal const string OcspStatus = "ocsp.status";

    /// <summary>X.509 revocation reason code.</summary>
    internal const string RevocationReason = "ca.revocation.reason";

    /// <summary>
    /// Structured error type; set to the exception class name or a short error code
    /// on all failure counter and span recordings.
    /// </summary>
    internal const string ErrorType = "error.type";

    /// <summary>HTTP response status code recorded on non-2xx result paths.</summary>
    internal const string HttpStatusCode = "http.response.status_code";
}

