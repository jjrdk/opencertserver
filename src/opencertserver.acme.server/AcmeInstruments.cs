namespace OpenCertServer.Acme.Server;

using System.Diagnostics;
using System.Diagnostics.Metrics;

/// <summary>OpenTelemetry instruments for all ACME request handlers (RFC 8555).</summary>
internal static class AcmeInstruments
{
    private static readonly Meter Meter = new(MetricNames.MeterName, "1.0.0");

    internal static readonly ActivitySource ActivitySource = new(MetricNames.MeterName, "1.0.0");

    // /directory
    internal static readonly Counter<long>     DirectoryRequests  = Meter.CreateCounter<long>     (MetricNames.DirectoryRequests,  description: "Total /directory requests");
    internal static readonly Counter<long>     DirectorySuccesses = Meter.CreateCounter<long>     (MetricNames.DirectorySuccesses, description: "Successful /directory responses");
    internal static readonly Counter<long>     DirectoryFailures  = Meter.CreateCounter<long>     (MetricNames.DirectoryFailures,  description: "Failed /directory responses");
    internal static readonly Histogram<double> DirectoryDuration  = Meter.CreateHistogram<double> (MetricNames.DirectoryDuration,  "s", "Duration of /directory requests");

    // /new-nonce
    internal static readonly Counter<long>     NewNonceRequests  = Meter.CreateCounter<long>     (MetricNames.NewNonceRequests);
    internal static readonly Counter<long>     NewNonceSuccesses = Meter.CreateCounter<long>     (MetricNames.NewNonceSuccesses);
    internal static readonly Counter<long>     NewNonceFailures  = Meter.CreateCounter<long>     (MetricNames.NewNonceFailures);
    internal static readonly Histogram<double> NewNonceDuration  = Meter.CreateHistogram<double> (MetricNames.NewNonceDuration, "s");

    // /new-account
    internal static readonly Counter<long>     NewAccountRequests  = Meter.CreateCounter<long>     (MetricNames.NewAccountRequests,  description: "Total /new-account requests");
    internal static readonly Counter<long>     NewAccountSuccesses = Meter.CreateCounter<long>     (MetricNames.NewAccountSuccesses, description: "Successful /new-account responses");
    internal static readonly Counter<long>     NewAccountFailures  = Meter.CreateCounter<long>     (MetricNames.NewAccountFailures,  description: "Failed /new-account responses");
    internal static readonly Histogram<double> NewAccountDuration  = Meter.CreateHistogram<double> (MetricNames.NewAccountDuration,  "s", "Duration of /new-account requests");

    // /new-order
    internal static readonly Counter<long>     NewOrderRequests  = Meter.CreateCounter<long>     (MetricNames.NewOrderRequests,  description: "Total /new-order requests");
    internal static readonly Counter<long>     NewOrderSuccesses = Meter.CreateCounter<long>     (MetricNames.NewOrderSuccesses, description: "Successful /new-order responses");
    internal static readonly Counter<long>     NewOrderFailures  = Meter.CreateCounter<long>     (MetricNames.NewOrderFailures,  description: "Failed /new-order responses");
    internal static readonly Histogram<double> NewOrderDuration  = Meter.CreateHistogram<double> (MetricNames.NewOrderDuration,  "s", "Duration of /new-order requests");

    // /order/{id}/finalize
    internal static readonly Counter<long>     OrderFinalizeRequests  = Meter.CreateCounter<long>     (MetricNames.OrderFinalizeRequests);
    internal static readonly Counter<long>     OrderFinalizeSuccesses = Meter.CreateCounter<long>     (MetricNames.OrderFinalizeSuccesses);
    internal static readonly Counter<long>     OrderFinalizeFailures  = Meter.CreateCounter<long>     (MetricNames.OrderFinalizeFailures);
    internal static readonly Histogram<double> OrderFinalizeDuration  = Meter.CreateHistogram<double> (MetricNames.OrderFinalizeDuration, "s");

    // /order/{id}/certificate
    internal static readonly Counter<long>     CertificateRequests  = Meter.CreateCounter<long>     (MetricNames.CertificateRequests);
    internal static readonly Counter<long>     CertificateSuccesses = Meter.CreateCounter<long>     (MetricNames.CertificateSuccesses);
    internal static readonly Counter<long>     CertificateFailures  = Meter.CreateCounter<long>     (MetricNames.CertificateFailures);
    internal static readonly Histogram<double> CertificateDuration  = Meter.CreateHistogram<double> (MetricNames.CertificateDuration, "s");

    // Challenge validation (ValidationWorker)
    internal static readonly Counter<long>       ChallengeValidationRequests  = Meter.CreateCounter<long>       (MetricNames.ChallengeValidationRequests,  description: "Total ACME challenge validation attempts");
    internal static readonly Counter<long>       ChallengeValidationSuccesses = Meter.CreateCounter<long>       (MetricNames.ChallengeValidationSuccesses, description: "Successful ACME challenge validations");
    internal static readonly Counter<long>       ChallengeValidationFailures  = Meter.CreateCounter<long>       (MetricNames.ChallengeValidationFailures,  description: "Failed ACME challenge validations");
    internal static readonly Histogram<double>   ChallengeValidationDuration  = Meter.CreateHistogram<double>   (MetricNames.ChallengeValidationDuration,  "s", "Duration of challenge validation");
    internal static readonly UpDownCounter<long> ChallengeValidationActive    = Meter.CreateUpDownCounter<long> (MetricNames.ChallengeValidationActive,    description: "Active pending ACME challenge validations");

    // /key-change
    internal static readonly Counter<long>     KeyChangeRequests  = Meter.CreateCounter<long>     (MetricNames.KeyChangeRequests);
    internal static readonly Counter<long>     KeyChangeSuccesses = Meter.CreateCounter<long>     (MetricNames.KeyChangeSuccesses);
    internal static readonly Counter<long>     KeyChangeFailures  = Meter.CreateCounter<long>     (MetricNames.KeyChangeFailures);
    internal static readonly Histogram<double> KeyChangeDuration  = Meter.CreateHistogram<double> (MetricNames.KeyChangeDuration, "s");

    // /revoke-cert
    internal static readonly Counter<long>     RevokeRequests  = Meter.CreateCounter<long>     (MetricNames.RevokeRequests);
    internal static readonly Counter<long>     RevokeSuccesses = Meter.CreateCounter<long>     (MetricNames.RevokeSuccesses);
    internal static readonly Counter<long>     RevokeFailures  = Meter.CreateCounter<long>     (MetricNames.RevokeFailures);
    internal static readonly Histogram<double> RevokeDuration  = Meter.CreateHistogram<double> (MetricNames.RevokeDuration, "s");
}
