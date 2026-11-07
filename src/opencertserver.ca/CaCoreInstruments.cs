namespace OpenCertServer.Ca;

using System.Diagnostics;
using System.Diagnostics.Metrics;

internal static class CaCoreInstruments
{
    private static readonly Meter Meter = new("opencertserver.ca.core", "1.0.0");
    internal static readonly ActivitySource ActivitySource = new("opencertserver.ca.core", "1.0.0");

    private static readonly Counter<long> Operations =
        Meter.CreateCounter<long>("opencertserver.ca.core.operations");
    private static readonly Counter<long> Successes =
        Meter.CreateCounter<long>("opencertserver.ca.core.successes");
    private static readonly Counter<long> Failures =
        Meter.CreateCounter<long>("opencertserver.ca.core.failures");
    private static readonly Histogram<double> Duration =
        Meter.CreateHistogram<double>("opencertserver.ca.core.duration", "s");

    internal static Operation Start(string operation)
    {
        Operations.Add(1, new KeyValuePair<string, object?>("operation", operation));
        return new Operation(operation, ActivitySource.StartActivity(operation));
    }

    internal sealed class Operation : IDisposable
    {
        private readonly string _name;
        private readonly Activity? _activity;
        private readonly long _startedAt = Stopwatch.GetTimestamp();
        private bool _succeeded;

        internal Operation(string name, Activity? activity)
        {
            _name = name;
            _activity = activity;
        }

        internal void Complete(bool succeeded = true) => _succeeded = succeeded;

        public void Dispose()
        {
            var tags = new KeyValuePair<string, object?>("operation", _name);
            if (_succeeded)
            {
                Successes.Add(1, tags);
            }
            else
            {
                Failures.Add(1, tags);
                _activity?.SetStatus(ActivityStatusCode.Error);
            }

            Duration.Record(Stopwatch.GetElapsedTime(_startedAt).TotalSeconds, tags);
            _activity?.Dispose();
        }
    }
}
