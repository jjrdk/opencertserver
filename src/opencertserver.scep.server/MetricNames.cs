namespace OpenCertServer.Scep.Server;

/// <summary>Centralised metric names for SCEP request instrumentation.</summary>
internal static class MetricNames
{
    internal const string MeterName = "opencertserver.scep";

    internal const string GetCaCapsRequests = "opencertserver.scep.getcacaps.requests";
    internal const string GetCaCapsSuccesses = "opencertserver.scep.getcacaps.successes";
    internal const string GetCaCapsFailures = "opencertserver.scep.getcacaps.failures";
    internal const string GetCaCapsDuration = "opencertserver.scep.getcacaps.duration";

    internal const string GetCaCertRequests = "opencertserver.scep.getcacert.requests";
    internal const string GetCaCertSuccesses = "opencertserver.scep.getcacert.successes";
    internal const string GetCaCertFailures = "opencertserver.scep.getcacert.failures";
    internal const string GetCaCertDuration = "opencertserver.scep.getcacert.duration";

    internal const string PkiOperationRequests = "opencertserver.scep.pkioperation.requests";
    internal const string PkiOperationSuccesses = "opencertserver.scep.pkioperation.successes";
    internal const string PkiOperationFailures = "opencertserver.scep.pkioperation.failures";
    internal const string PkiOperationDuration = "opencertserver.scep.pkioperation.duration";

    internal const string UnsupportedOperationRequests = "opencertserver.scep.unsupported.requests";
    internal const string UnsupportedOperationSuccesses = "opencertserver.scep.unsupported.successes";
    internal const string UnsupportedOperationFailures = "opencertserver.scep.unsupported.failures";
    internal const string UnsupportedOperationDuration = "opencertserver.scep.unsupported.duration";
}
