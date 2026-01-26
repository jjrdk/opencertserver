using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca;

public interface IStoreCertificates
{
    Task AddCertificate(X509Certificate2 certificate);

    Task<bool> RemoveCertificate(string serialNumber, X509RevocationReason reason);

    IAsyncEnumerable<CertificateItemInfo> GetRevocationList(int page = 0, int pageSize = 100);

    IAsyncEnumerable<CertificateItemInfo> GetInventory(int page = 0, int pageSize = 100);

    IAsyncEnumerable<X509Certificate2> GetCertificatesById(params IEnumerable<ReadOnlyMemory<byte>> ids);

    IAsyncEnumerable<X509Certificate2> GetCertificatesByThumbprint(IEnumerable<ReadOnlyMemory<char>> thumbprint);
}
