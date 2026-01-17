namespace OpenCertServer.Ca.Utils;

using System.Security.Cryptography.X509Certificates;

public interface IValidateCertificateRequests
{
    string? Validate(CertificateRequest request, X509Certificate2? reenrollingFrom = null);
}
