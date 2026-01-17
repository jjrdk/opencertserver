using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca;

public interface IStoreCertificates
{
    void AddCertificate(X509Certificate2 certificate);

    bool RemoveCertificate(string serialNumber, X509RevocationReason reason);

    IEnumerable<CertificateItem> GetRevocationList(int page = 0, int pageSize = 100);

    CertificateItem[] GetInventory(int page = 0, int pageSize = 100);
}
