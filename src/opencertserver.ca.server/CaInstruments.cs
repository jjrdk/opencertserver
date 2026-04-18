namespace OpenCertServer.Ca.Server;

using System.Diagnostics;
using System.Diagnostics.Metrics;

/// <summary>OpenTelemetry instruments for CA, OCSP, and CRL request handlers (RFC 6960, RFC 5280).</summary>
internal static class CaInstruments
{
    private static readonly Meter Meter = new(MetricNames.MeterName, "1.0.0");

    internal static readonly ActivitySource ActivitySource = new(MetricNames.MeterName, "1.0.0");

    // OCSP – RFC 6960
    internal static readonly Counter<long>     OcspRequests  = Meter.CreateCounter<long>     (MetricNames.OcspRequests,  description: "Total OCSP requests");
    internal static readonly Counter<long>     OcspSuccesses = Meter.CreateCounter<long>     (MetricNames.OcspSuccesses, description: "Successful OCSP responses");
    internal static readonly Counter<long>     OcspFailures  = Meter.CreateCounter<long>     (MetricNames.OcspFailures,  description: "Failed OCSP responses");
    internal static readonly Histogram<double> OcspDuration  = Meter.CreateHistogram<double> (MetricNames.OcspDuration,  "s", "Duration of OCSP request processing");

    // CRL requests – RFC 5280
    internal static readonly Counter<long>     CrlRequests  = Meter.CreateCounter<long>     (MetricNames.CrlRequests,  description: "Total CRL requests");
    internal static readonly Counter<long>     CrlSuccesses = Meter.CreateCounter<long>     (MetricNames.CrlSuccesses, description: "Successful CRL responses");
    internal static readonly Counter<long>     CrlFailures  = Meter.CreateCounter<long>     (MetricNames.CrlFailures,  description: "Failed CRL responses");
    internal static readonly Histogram<double> CrlDuration  = Meter.CreateHistogram<double> (MetricNames.CrlDuration,  "s", "Duration of CRL requests");

    // CRL generation
    internal static readonly Counter<long>     CrlGenerationRequests  = Meter.CreateCounter<long>     (MetricNames.CrlGenerationRequests,  description: "Total CRL generation requests");
    internal static readonly Counter<long>     CrlGenerationSuccesses = Meter.CreateCounter<long>     (MetricNames.CrlGenerationSuccesses, description: "Successful CRL generations");
    internal static readonly Counter<long>     CrlGenerationFailures  = Meter.CreateCounter<long>     (MetricNames.CrlGenerationFailures,  description: "Failed CRL generations");
    internal static readonly Histogram<double> CrlGenerationDuration  = Meter.CreateHistogram<double> (MetricNames.CrlGenerationDuration,  "s", "Duration of CRL generation");

    // /ca/csr
    internal static readonly Counter<long>     CsrRequests  = Meter.CreateCounter<long>     (MetricNames.CsrRequests,  description: "Total CSR signing requests");
    internal static readonly Counter<long>     CsrSuccesses = Meter.CreateCounter<long>     (MetricNames.CsrSuccesses, description: "Successful CSR signings");
    internal static readonly Counter<long>     CsrFailures  = Meter.CreateCounter<long>     (MetricNames.CsrFailures,  description: "Failed CSR signings");
    internal static readonly Histogram<double> CsrDuration  = Meter.CreateHistogram<double> (MetricNames.CsrDuration,  "s", "Duration of CSR signing");

    // /ca/revoke
    internal static readonly Counter<long>     RevocationRequests  = Meter.CreateCounter<long>     (MetricNames.RevocationRequests,  description: "Total revocation requests");
    internal static readonly Counter<long>     RevocationSuccesses = Meter.CreateCounter<long>     (MetricNames.RevocationSuccesses, description: "Successful revocations");
    internal static readonly Counter<long>     RevocationFailures  = Meter.CreateCounter<long>     (MetricNames.RevocationFailures,  description: "Failed revocations");
    internal static readonly Histogram<double> RevocationDuration  = Meter.CreateHistogram<double> (MetricNames.RevocationDuration,  "s", "Duration of revocation requests");

    // /ca/inventory
    internal static readonly Counter<long>     InventoryRequests  = Meter.CreateCounter<long>     (MetricNames.InventoryRequests,  description: "Total inventory requests");
    internal static readonly Counter<long>     InventorySuccesses = Meter.CreateCounter<long>     (MetricNames.InventorySuccesses, description: "Successful inventory responses");
    internal static readonly Counter<long>     InventoryFailures  = Meter.CreateCounter<long>     (MetricNames.InventoryFailures,  description: "Failed inventory responses");
    internal static readonly Histogram<double> InventoryDuration  = Meter.CreateHistogram<double> (MetricNames.InventoryDuration,  "s", "Duration of inventory requests");

    // /ca/certificates (retrieval by thumbprint / id)
    internal static readonly Counter<long>     CertRetrievalRequests  = Meter.CreateCounter<long>     (MetricNames.CertRetrievalRequests,  description: "Total certificate retrieval requests");
    internal static readonly Counter<long>     CertRetrievalSuccesses = Meter.CreateCounter<long>     (MetricNames.CertRetrievalSuccesses, description: "Successful certificate retrievals");
    internal static readonly Counter<long>     CertRetrievalFailures  = Meter.CreateCounter<long>     (MetricNames.CertRetrievalFailures,  description: "Failed certificate retrievals");
    internal static readonly Histogram<double> CertRetrievalDuration  = Meter.CreateHistogram<double> (MetricNames.CertRetrievalDuration,  "s", "Duration of certificate retrieval requests");
}

