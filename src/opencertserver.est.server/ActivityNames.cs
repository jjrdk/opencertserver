namespace OpenCertServer.Est.Server;

/// <summary>
/// Centralised activity (span) name constants for all EST OpenTelemetry traces.
/// All spans MUST reference these constants; never use inline string literals for activity names.
/// </summary>
internal static class ActivityNames
{
    internal const string CaCerts      = "opencertserver.est.cacerts";
    internal const string SimpleEnroll = "opencertserver.est.simpleenroll";
    internal const string SimpleReEnroll = "opencertserver.est.simplereenroll";
    internal const string CsrAttrs    = "opencertserver.est.csrattrs";
    internal const string ServerKeyGen = "opencertserver.est.serverkeygen";
}

