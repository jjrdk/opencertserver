namespace OpenCertServer.Ca.Server;

/// <summary>
/// Centralised activity (span) name constants for all CA/OCSP/CRL OpenTelemetry traces.
/// All spans MUST reference these constants; never use inline string literals for activity names.
/// </summary>
internal static class ActivityNames
{
    internal const string OcspRequest    = "opencertserver.ocsp.request";
    internal const string CrlRequest     = "opencertserver.crl.request";
    internal const string CrlGeneration  = "opencertserver.crl.generation";
    internal const string CsrSign        = "opencertserver.ca.csr";
    internal const string Revoke         = "opencertserver.ca.revoke";
    internal const string Inventory             = "opencertserver.ca.inventory";
    internal const string CertificateRetrieval  = "opencertserver.ca.certretrieval";
}

