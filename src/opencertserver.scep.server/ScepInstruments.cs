namespace OpenCertServer.Scep.Server;

using System.Diagnostics;
using System.Diagnostics.Metrics;

/// <summary>OpenTelemetry instruments for SCEP request handling.</summary>
internal static class ScepInstruments
{
    internal enum Operation
    {
        GetCaCaps,
        GetCaCert,
        PkiOperation,
        Unsupported
    }

    private static readonly Meter Meter = new(MetricNames.MeterName, "1.0.0");

    internal static readonly ActivitySource ActivitySource = new(MetricNames.MeterName, "1.0.0");

    private static readonly Counter<long> GetCaCapsRequests = Meter.CreateCounter<long>(MetricNames.GetCaCapsRequests);
    private static readonly Counter<long> GetCaCapsSuccesses = Meter.CreateCounter<long>(MetricNames.GetCaCapsSuccesses);
    private static readonly Counter<long> GetCaCapsFailures = Meter.CreateCounter<long>(MetricNames.GetCaCapsFailures);
    private static readonly Histogram<double> GetCaCapsDuration = Meter.CreateHistogram<double>(MetricNames.GetCaCapsDuration, "s");

    private static readonly Counter<long> GetCaCertRequests = Meter.CreateCounter<long>(MetricNames.GetCaCertRequests);
    private static readonly Counter<long> GetCaCertSuccesses = Meter.CreateCounter<long>(MetricNames.GetCaCertSuccesses);
    private static readonly Counter<long> GetCaCertFailures = Meter.CreateCounter<long>(MetricNames.GetCaCertFailures);
    private static readonly Histogram<double> GetCaCertDuration = Meter.CreateHistogram<double>(MetricNames.GetCaCertDuration, "s");

    private static readonly Counter<long> PkiOperationRequests = Meter.CreateCounter<long>(MetricNames.PkiOperationRequests);
    private static readonly Counter<long> PkiOperationSuccesses = Meter.CreateCounter<long>(MetricNames.PkiOperationSuccesses);
    private static readonly Counter<long> PkiOperationFailures = Meter.CreateCounter<long>(MetricNames.PkiOperationFailures);
    private static readonly Histogram<double> PkiOperationDuration = Meter.CreateHistogram<double>(MetricNames.PkiOperationDuration, "s");

    private static readonly Counter<long> UnsupportedOperationRequests = Meter.CreateCounter<long>(MetricNames.UnsupportedOperationRequests);
    private static readonly Counter<long> UnsupportedOperationSuccesses = Meter.CreateCounter<long>(MetricNames.UnsupportedOperationSuccesses);
    private static readonly Counter<long> UnsupportedOperationFailures = Meter.CreateCounter<long>(MetricNames.UnsupportedOperationFailures);
    private static readonly Histogram<double> UnsupportedOperationDuration = Meter.CreateHistogram<double>(MetricNames.UnsupportedOperationDuration, "s");

    internal static void RecordRequest(Operation operation) => Counters(operation).Requests.Add(1);

    internal static void RecordSuccess(Operation operation) => Counters(operation).Successes.Add(1);

    internal static void RecordFailure(Operation operation) => Counters(operation).Failures.Add(1);

    internal static void RecordDuration(Operation operation, double seconds) => Counters(operation).Duration.Record(seconds);

    private static (Counter<long> Requests, Counter<long> Successes, Counter<long> Failures, Histogram<double> Duration)
        Counters(Operation operation) => operation switch
        {
            Operation.GetCaCaps => (GetCaCapsRequests, GetCaCapsSuccesses, GetCaCapsFailures, GetCaCapsDuration),
            Operation.GetCaCert => (GetCaCertRequests, GetCaCertSuccesses, GetCaCertFailures, GetCaCertDuration),
            Operation.PkiOperation => (PkiOperationRequests, PkiOperationSuccesses, PkiOperationFailures, PkiOperationDuration),
            _ => (UnsupportedOperationRequests, UnsupportedOperationSuccesses, UnsupportedOperationFailures, UnsupportedOperationDuration)
        };
}
