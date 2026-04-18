namespace OpenCertServer.Est.Server;

using System.Diagnostics;
using System.Diagnostics.Metrics;

/// <summary>OpenTelemetry instruments for all EST request handlers (RFC 7030).</summary>
internal static class EstInstruments
{
    private static readonly Meter Meter = new(MetricNames.MeterName, "1.0.0");

    internal static readonly ActivitySource ActivitySource = new(MetricNames.MeterName, "1.0.0");

    // /cacerts
    internal static readonly Counter<long>     CaCertsRequests  = Meter.CreateCounter<long>     (MetricNames.CaCertsRequests,  description: "Total /cacerts requests");
    internal static readonly Counter<long>     CaCertsSuccesses = Meter.CreateCounter<long>     (MetricNames.CaCertsSuccesses, description: "Successful /cacerts responses");
    internal static readonly Counter<long>     CaCertsFailures  = Meter.CreateCounter<long>     (MetricNames.CaCertsFailures,  description: "Failed /cacerts responses");
    internal static readonly Histogram<double> CaCertsDuration  = Meter.CreateHistogram<double> (MetricNames.CaCertsDuration,  "s", "Duration of /cacerts requests");

    // /simpleenroll
    internal static readonly Counter<long>     SimpleEnrollRequests  = Meter.CreateCounter<long>     (MetricNames.SimpleEnrollRequests,  description: "Total /simpleenroll requests");
    internal static readonly Counter<long>     SimpleEnrollSuccesses = Meter.CreateCounter<long>     (MetricNames.SimpleEnrollSuccesses, description: "Successful /simpleenroll responses");
    internal static readonly Counter<long>     SimpleEnrollFailures  = Meter.CreateCounter<long>     (MetricNames.SimpleEnrollFailures,  description: "Failed /simpleenroll responses");
    internal static readonly Histogram<double> SimpleEnrollDuration  = Meter.CreateHistogram<double> (MetricNames.SimpleEnrollDuration,  "s", "Duration of /simpleenroll requests");

    // /simplereenroll
    internal static readonly Counter<long>     SimpleReEnrollRequests  = Meter.CreateCounter<long>     (MetricNames.SimpleReEnrollRequests,  description: "Total /simplereenroll requests");
    internal static readonly Counter<long>     SimpleReEnrollSuccesses = Meter.CreateCounter<long>     (MetricNames.SimpleReEnrollSuccesses, description: "Successful /simplereenroll responses");
    internal static readonly Counter<long>     SimpleReEnrollFailures  = Meter.CreateCounter<long>     (MetricNames.SimpleReEnrollFailures,  description: "Failed /simplereenroll responses");
    internal static readonly Histogram<double> SimpleReEnrollDuration  = Meter.CreateHistogram<double> (MetricNames.SimpleReEnrollDuration,  "s", "Duration of /simplereenroll requests");

    // /csrattrs
    internal static readonly Counter<long>     CsrAttrsRequests  = Meter.CreateCounter<long>     (MetricNames.CsrAttrsRequests,  description: "Total /csrattrs requests");
    internal static readonly Counter<long>     CsrAttrsSuccesses = Meter.CreateCounter<long>     (MetricNames.CsrAttrsSuccesses, description: "Successful /csrattrs responses");
    internal static readonly Counter<long>     CsrAttrsFailures  = Meter.CreateCounter<long>     (MetricNames.CsrAttrsFailures,  description: "Failed /csrattrs responses");
    internal static readonly Histogram<double> CsrAttrsDuration  = Meter.CreateHistogram<double> (MetricNames.CsrAttrsDuration,  "s", "Duration of /csrattrs requests");

    // /serverkeygen
    internal static readonly Counter<long>     ServerKeyGenRequests  = Meter.CreateCounter<long>     (MetricNames.ServerKeyGenRequests,  description: "Total /serverkeygen requests");
    internal static readonly Counter<long>     ServerKeyGenSuccesses = Meter.CreateCounter<long>     (MetricNames.ServerKeyGenSuccesses, description: "Successful /serverkeygen responses");
    internal static readonly Counter<long>     ServerKeyGenFailures  = Meter.CreateCounter<long>     (MetricNames.ServerKeyGenFailures,  description: "Failed /serverkeygen responses");
    internal static readonly Histogram<double> ServerKeyGenDuration  = Meter.CreateHistogram<double> (MetricNames.ServerKeyGenDuration,  "s", "Duration of /serverkeygen requests");
}
