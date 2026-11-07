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
    [Obsolete("Use the overload that includes the issuing profile to support re-enrollment provenance.", error: false)]
    Task AddCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default) =>
        AddCertificate(certificate, null!, cancellationToken);

    /// <summary>
    /// Stores a certificate together with the resolved name of its issuing profile.
    /// Stores must override this overload and <see cref="GetIssuingProfile"/> to support
    /// profile-bound re-enrollment. The compatibility implementation stores no provenance.
    /// </summary>
    Task AddCertificate(
        X509Certificate2 certificate,
        string? issuingProfile,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns trusted issuance metadata for the exact certificate thumbprint, or null when
    /// provenance is unavailable. Never infer this value from a CSR, subject, serial or issuer.
    /// The default request validator refuses re-enrollment when provenance is unavailable.
    /// </summary>
    Task<string?> GetIssuingProfile(string thumbprint, CancellationToken cancellationToken = default) =>
        Task.FromResult<string?>(null);

    /// <summary>
    /// Removes a certificate from the store, recording the revocation reason. This overload is provided for
    /// compatibility with implementations that do not support issuing profile provenance.
    /// Implementations must only remove certificates whose recorded issuing profile matches the default profile (null)
    /// so that a profile's CRL never discloses another profile's revocations.
    /// </summary>
    /// <param name="serialNumber">The serial number of the certificate to remove.</param>
    /// <param name="reason">The revocation reason.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains a boolean indicating
    /// whether the certificate was successfully removed.</returns>
    [Obsolete("Use the overload that includes the issuing profile to support re-enrollment provenance.", error: false)]
    Task<bool> RemoveCertificate(
        string serialNumber,
        X509RevocationReason reason,
        CancellationToken cancellationToken = default) => RemoveCertificate(serialNumber, null, reason, cancellationToken);

    /// <summary>
    /// Removes a certificate from the store, recording the revocation reason.
    /// Implementations must only remove certificates whose recorded issuing profile matches
    /// </summary>
    /// <param name="serialNumber">The serial number of the certificate to remove.</param>
    /// <param name="issuingProfile">The name of the issuing profile.</param>
    /// <param name="reason">The revocation reason.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task that represents the asynchronous operation. The task result contains a boolean indicating whether the certificate was successfully removed.</returns>
    Task<bool> RemoveCertificate(
        string serialNumber,
        string? issuingProfile,
        X509RevocationReason reason,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns one 0-based page of revoked certificates issued under <paramref name="issuingProfile"/>.
    /// Implementations must only return certificates whose recorded issuing profile matches
    /// (ordinal comparison) so that a profile's CRL never discloses another profile's revocations.
    /// Certificates stored without an issuing profile only match a <see langword="null"/> profile.
    /// </summary>
    /// <param name="issuingProfile">The name of the issuing profile whose revocations are requested.</param>
    /// <param name="page">The 0-based page index.</param>
    /// <param name="pageSize">The maximum number of entries per page.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    IAsyncEnumerable<CertificateItemInfo> GetRevocationList(
        string? issuingProfile,
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

    [Obsolete("Use the overload that includes the issuing profile to support re-enrollment provenance.", error: false)]
    IAsyncEnumerable<X509Certificate2> GetCertificatesById(
        CancellationToken cancellationToken,
        params IEnumerable<ReadOnlyMemory<byte>> ids) => GetCertificatesById(null, cancellationToken, ids);

    IAsyncEnumerable<X509Certificate2> GetCertificatesById(
        string? issuingProfile,
        CancellationToken cancellationToken,
        params IEnumerable<ReadOnlyMemory<byte>> ids);

    IAsyncEnumerable<X509Certificate2> GetCertificatesByThumbprint(
        IEnumerable<ReadOnlyMemory<char>> thumbprint,
        CancellationToken cancellationToken = default);
}
