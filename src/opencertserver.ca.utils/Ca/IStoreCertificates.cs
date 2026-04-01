namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Defines the IStoreCertificates interface.
/// </summary>
/// <summary>
/// Represents the IStoreCertificates.
/// </summary>
public interface IStoreCertificates
{
    Task AddCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default);

    Task<bool> RemoveCertificate(
        string serialNumber,
        X509RevocationReason reason,
        CancellationToken cancellationToken = default);

    IAsyncEnumerable<CertificateItemInfo> GetRevocationList(
        int page = 0,
        int pageSize = 100,
        CancellationToken cancellationToken = default);

    Task<(CertId, CertificateStatus, RevokedInfo?)> GetCertificateStatus(
        CertId certId,
        CancellationToken cancellationToken = default);

    IAsyncEnumerable<CertificateItemInfo> GetInventory(
        int page = 0,
        int pageSize = 100,
        CancellationToken cancellationToken = default);

    IAsyncEnumerable<X509Certificate2> GetCertificatesById(
        CancellationToken cancellationToken,
        params IEnumerable<ReadOnlyMemory<byte>> ids);

    IAsyncEnumerable<X509Certificate2> GetCertificatesByThumbprint(
        IEnumerable<ReadOnlyMemory<char>> thumbprint,
        CancellationToken cancellationToken = default);
}
