namespace OpenCertServer.Data.PostgreSql;

using System.Diagnostics;
using System.Diagnostics.Metrics;

internal static class PostgreSqlInstruments
{
    private static readonly Meter Meter = new("opencertserver.data.postgresql", "1.0.0");
    internal static readonly ActivitySource ActivitySource = new("opencertserver.data.postgresql", "1.0.0");
    private static readonly Counter<long> Operations =
        Meter.CreateCounter<long>("opencertserver.data.postgresql.operations");
    private static readonly Counter<long> Failures =
        Meter.CreateCounter<long>("opencertserver.data.postgresql.failures");
    private static readonly Counter<long> Successes =
        Meter.CreateCounter<long>("opencertserver.data.postgresql.successes");
    private static readonly Histogram<double> Duration =
        Meter.CreateHistogram<double>("opencertserver.data.postgresql.duration", "s");

    internal static Operation Start(string name)
    {
        Operations.Add(1, new KeyValuePair<string, object?>("operation", name));
        return new Operation(name, ActivitySource.StartActivity(name));
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

        internal void Complete() => _succeeded = true;

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
