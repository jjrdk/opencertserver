namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Cryptography.X509Certificates;
using Ocsp;

/// <summary>
/// Defines the IStoreCertificates interface.
/// </summary>
/// <summary>
/// Represents the IStoreCertificates.
/// </summary>
public interface IStoreCertificates
{
    Task AddCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default);

    /// <summary>
    /// Stores a certificate together with the resolved name of its issuing profile.
    /// Stores must override this overload and <see cref="GetIssuingProfile"/> to support
    /// profile-bound re-enrollment. The compatibility implementation stores no provenance.
    /// </summary>
    Task AddCertificate(
        X509Certificate2 certificate,
        string issuingProfile,
        CancellationToken cancellationToken = default) => AddCertificate(certificate, cancellationToken);

    /// <summary>
    /// Returns trusted issuance metadata for the exact certificate thumbprint, or null when
    /// provenance is unavailable. Never infer this value from a CSR, subject, serial or issuer.
    /// The default request validator refuses re-enrollment when provenance is unavailable.
    /// </summary>
    Task<string?> GetIssuingProfile(string thumbprint, CancellationToken cancellationToken = default) =>
        Task.FromResult<string?>(null);

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
