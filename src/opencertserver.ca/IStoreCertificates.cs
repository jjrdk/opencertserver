using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca;

public interface IStoreCertificates
{
    void AddCertificate(X509Certificate2 certificate);

    bool RemoveCertificate(string serialNumber, X509RevocationReason reason);

    byte[] GetRevocationList();
}
