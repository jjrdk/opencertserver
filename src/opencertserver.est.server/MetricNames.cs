namespace OpenCertServer.Est.Server;

/// <summary>
/// Centralised metric name constants for all EST OpenTelemetry instruments.
/// All metric instrument creation MUST reference these constants.
/// </summary>
internal static class MetricNames
{
    internal const string MeterName = "opencertserver.est";

    // /cacerts
    internal const string CaCertsRequests  = "opencertserver.est.cacerts.requests";
    internal const string CaCertsSuccesses = "opencertserver.est.cacerts.successes";
    internal const string CaCertsFailures  = "opencertserver.est.cacerts.failures";
    internal const string CaCertsDuration  = "opencertserver.est.cacerts.duration";

    // /simpleenroll
    internal const string SimpleEnrollRequests  = "opencertserver.est.simpleenroll.requests";
    internal const string SimpleEnrollSuccesses = "opencertserver.est.simpleenroll.successes";
    internal const string SimpleEnrollFailures  = "opencertserver.est.simpleenroll.failures";
    internal const string SimpleEnrollDuration  = "opencertserver.est.simpleenroll.duration";

    // /simplereenroll
    internal const string SimpleReEnrollRequests  = "opencertserver.est.simplereenroll.requests";
    internal const string SimpleReEnrollSuccesses = "opencertserver.est.simplereenroll.successes";
    internal const string SimpleReEnrollFailures  = "opencertserver.est.simplereenroll.failures";
    internal const string SimpleReEnrollDuration  = "opencertserver.est.simplereenroll.duration";

    // /csrattrs
    internal const string CsrAttrsRequests  = "opencertserver.est.csrattrs.requests";
    internal const string CsrAttrsSuccesses = "opencertserver.est.csrattrs.successes";
    internal const string CsrAttrsFailures  = "opencertserver.est.csrattrs.failures";
    internal const string CsrAttrsDuration  = "opencertserver.est.csrattrs.duration";

    // /serverkeygen
    internal const string ServerKeyGenRequests  = "opencertserver.est.serverkeygen.requests";
    internal const string ServerKeyGenSuccesses = "opencertserver.est.serverkeygen.successes";
    internal const string ServerKeyGenFailures  = "opencertserver.est.serverkeygen.failures";
    internal const string ServerKeyGenDuration  = "opencertserver.est.serverkeygen.duration";
}

