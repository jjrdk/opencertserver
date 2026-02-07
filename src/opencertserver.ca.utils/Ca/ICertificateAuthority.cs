namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Cryptography.X509Certificates;

public interface ICertificateAuthority
{
    SignCertificateResponse SignCertificateRequest(CertificateRequest request, X509Certificate2? reenrollingFrom = null);

    SignCertificateResponse SignCertificateRequestPem(string request);

    X509Certificate2Collection GetRootCertificates();

    Task<bool> RevokeCertificate(string serialNumber, X509RevocationReason reason);

    Task<byte[]> GetRevocationList();
}
