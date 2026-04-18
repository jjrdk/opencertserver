namespace OpenCertServer.Ca.Server;

/// <summary>
/// Centralised metric name constants for all CA/OCSP/CRL OpenTelemetry instruments.
/// All metric instrument creation MUST reference these constants.
/// </summary>
internal static class MetricNames
{
    internal const string MeterName = "opencertserver.ca";

    // OCSP – RFC 6960
    internal const string OcspRequests  = "opencertserver.ocsp.request.requests";
    internal const string OcspSuccesses = "opencertserver.ocsp.request.successes";
    internal const string OcspFailures  = "opencertserver.ocsp.request.failures";
    internal const string OcspDuration  = "opencertserver.ocsp.request.duration";

    // CRL requests – RFC 5280
    internal const string CrlRequests  = "opencertserver.crl.request.requests";
    internal const string CrlSuccesses = "opencertserver.crl.request.successes";
    internal const string CrlFailures  = "opencertserver.crl.request.failures";
    internal const string CrlDuration  = "opencertserver.crl.request.duration";

    // CRL generation
    internal const string CrlGenerationRequests  = "opencertserver.crl.generation.requests";
    internal const string CrlGenerationSuccesses = "opencertserver.crl.generation.successes";
    internal const string CrlGenerationFailures  = "opencertserver.crl.generation.failures";
    internal const string CrlGenerationDuration  = "opencertserver.crl.generation.duration";

    // /ca/csr (CSR signing)
    internal const string CsrRequests  = "opencertserver.ca.csr.requests";
    internal const string CsrSuccesses = "opencertserver.ca.csr.successes";
    internal const string CsrFailures  = "opencertserver.ca.csr.failures";
    internal const string CsrDuration  = "opencertserver.ca.csr.duration";

    // /ca/revoke
    internal const string RevocationRequests  = "opencertserver.ca.revoke.requests";
    internal const string RevocationSuccesses = "opencertserver.ca.revoke.successes";
    internal const string RevocationFailures  = "opencertserver.ca.revoke.failures";
    internal const string RevocationDuration  = "opencertserver.ca.revoke.duration";

    // /ca/inventory
    internal const string InventoryRequests  = "opencertserver.ca.inventory.requests";
    internal const string InventorySuccesses = "opencertserver.ca.inventory.successes";
    internal const string InventoryFailures  = "opencertserver.ca.inventory.failures";
    internal const string InventoryDuration  = "opencertserver.ca.inventory.duration";

    // /ca/certificates (retrieval by thumbprint / id)
    internal const string CertRetrievalRequests  = "opencertserver.ca.certretrieval.requests";
    internal const string CertRetrievalSuccesses = "opencertserver.ca.certretrieval.successes";
    internal const string CertRetrievalFailures  = "opencertserver.ca.certretrieval.failures";
    internal const string CertRetrievalDuration  = "opencertserver.ca.certretrieval.duration";
}

