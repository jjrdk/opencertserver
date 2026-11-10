namespace OpenCertServer.Contrib.Intune;

using System.Diagnostics;
using System.Diagnostics.Metrics;

/// <summary>OpenTelemetry instruments for Intune validation, notifications and revocation sync.</summary>
internal static class IntuneInstruments
{
    private static readonly Meter Meter = new(MetricNames.MeterName, "1.0.0");

    internal static readonly ActivitySource ActivitySource = new(MetricNames.MeterName, "1.0.0");

    internal static readonly Counter<long> ChallengeValidationRequests = Meter.CreateCounter<long>(MetricNames.ChallengeValidationRequests);
    internal static readonly Counter<long> ChallengeValidationSuccesses = Meter.CreateCounter<long>(MetricNames.ChallengeValidationSuccesses);
    internal static readonly Counter<long> ChallengeValidationFailures = Meter.CreateCounter<long>(MetricNames.ChallengeValidationFailures);
    internal static readonly Histogram<double> ChallengeValidationDuration = Meter.CreateHistogram<double>(MetricNames.ChallengeValidationDuration, "s");

    internal static readonly Counter<long> SuccessNotificationRequests = Meter.CreateCounter<long>(MetricNames.SuccessNotificationRequests);
    internal static readonly Counter<long> SuccessNotificationSuccesses = Meter.CreateCounter<long>(MetricNames.SuccessNotificationSuccesses);
    internal static readonly Counter<long> SuccessNotificationFailures = Meter.CreateCounter<long>(MetricNames.SuccessNotificationFailures);
    internal static readonly Histogram<double> SuccessNotificationDuration = Meter.CreateHistogram<double>(MetricNames.SuccessNotificationDuration, "s");

    internal static readonly Counter<long> FailureNotificationRequests = Meter.CreateCounter<long>(MetricNames.FailureNotificationRequests);
    internal static readonly Counter<long> FailureNotificationSuccesses = Meter.CreateCounter<long>(MetricNames.FailureNotificationSuccesses);
    internal static readonly Counter<long> FailureNotificationFailures = Meter.CreateCounter<long>(MetricNames.FailureNotificationFailures);
    internal static readonly Histogram<double> FailureNotificationDuration = Meter.CreateHistogram<double>(MetricNames.FailureNotificationDuration, "s");

    internal static readonly Counter<long> RevocationSyncRequests = Meter.CreateCounter<long>(MetricNames.RevocationSyncRequests);
    internal static readonly Counter<long> RevocationSyncSuccesses = Meter.CreateCounter<long>(MetricNames.RevocationSyncSuccesses);
    internal static readonly Counter<long> RevocationSyncFailures = Meter.CreateCounter<long>(MetricNames.RevocationSyncFailures);
    internal static readonly Histogram<double> RevocationSyncDuration = Meter.CreateHistogram<double>(MetricNames.RevocationSyncDuration, "s");
}
