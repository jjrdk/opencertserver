namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

public interface ICertificateAuthority
{
    SignCertificateResponse SignCertificateRequest(
        CertificateRequest request,
        string? profileName = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null);

    SignCertificateResponse SignCertificateRequestPem(
        string request,
        string? profileName = null,
        ClaimsIdentity? requestor = null,
        X509Certificate2? reenrollingFrom = null);

    X509Certificate2Collection GetRootCertificates(string? profileName = null);

    Task<bool> RevokeCertificate(string serialNumber, X509RevocationReason reason);

    Task<byte[]> GetRevocationList(string? profileName = null);
}
