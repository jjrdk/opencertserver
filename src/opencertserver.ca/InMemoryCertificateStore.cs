using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca;

public class InMemoryCertificateStore : IStoreCertificates
{
    private readonly Dictionary<string, CertificateItem> _certificates = new();

    public void AddCertificate(X509Certificate2 certificate)
    {
        _certificates.Add(certificate.GetSerialNumberString(), CertificateItem.FromX509Certificate2(certificate));
    }

    public bool RemoveCertificate(string serialNumber, X509RevocationReason reason)
    {
        if (!_certificates.TryGetValue(serialNumber, out var certificateItem))
        {
            return false;
        }
        certificateItem.RevocationDate = DateTimeOffset.UtcNow;
        certificateItem.RevocationReason = reason;
        return true;
    }

    public IEnumerable<CertificateItem> GetRevocationList(int page = 0, int pageSize = 100)
    {
        return _certificates
            .OrderBy(x => x.Key)
            .Where(x => x.Value.IsRevoked)
            .Skip(page * pageSize)
            .Take(pageSize)
            .Select(x => x.Value)
            .ToArray();
    }

    public CertificateItem[] GetInventory(int page = 0, int pageSize = 100)
    {
        return _certificates
            .OrderBy(x => x.Key)
            .Skip(page * pageSize)
            .Take(pageSize)
            .Select(x => x.Value)
            .ToArray();
    }
}
