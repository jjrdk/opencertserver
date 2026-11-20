namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Cryptography.X509Certificates;
using Ocsp;

/// <summary>
/// Provides an in-memory implementation of <see cref="IStoreCertificates"/> for certificate inventory and revocation tracking.
/// </summary>
public class InMemoryCertificateStore : IStoreCertificates
{
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    private readonly Dictionary<(string, string?), CertificateItem> _certificates = new();

    /// <inheritdoc />
    public Task AddCertificate(
        X509Certificate2 certificate,
        string? issuingProfile,
        CancellationToken cancellationToken = default)
    {
        var item = CertificateItem.FromX509Certificate2(certificate);
        item.IssuingProfile = issuingProfile;
        _certificates.Add((item.SerialNumber, issuingProfile), item);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<string?> GetIssuingProfile(string thumbprint, CancellationToken cancellationToken = default)
    {
        var item = _certificates.Values.SingleOrDefault(item =>
            string.Equals(item.Thumbprint, thumbprint, StringComparison.OrdinalIgnoreCase));
        return Task.FromResult(item?.IssuingProfile);
    }

    /// <inheritdoc />
    public Task<bool> RemoveCertificate(
        string serialNumber,
        string? issuingProfile,
        X509RevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        if (!_certificates.TryGetValue((serialNumber, issuingProfile), out var certificateItem))
        {
            return Task.FromResult(false);
        }

        certificateItem.RevocationDate = DateTimeOffset.UtcNow;
        certificateItem.RevocationReason = reason;
        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public IAsyncEnumerable<CertificateItemInfo> GetRevocationList(
        string? issuingProfile,
        int page = 0,
        int pageSize = 100,
        CancellationToken cancellationToken = default)
    {
        return _certificates
            .Where(x => x.Value.IsRevoked
             && string.Equals(x.Value.IssuingProfile, issuingProfile, StringComparison.Ordinal))
            .Skip(page * pageSize)
            .Take(pageSize)
            .OrderBy(x => x.Key.Item1, StringComparer.Ordinal)
            .Select(x => x.Value.AsInfo())
            .ToAsyncEnumerable();
    }

    /// <inheritdoc />
    public Task<(CertId, CertificateStatus, RevokedInfo?)> GetCertificateStatus(
        CertId certId,
        CancellationToken cancellationToken = default)
    {
        var kvp = _certificates.FirstOrDefault(x => x.Key.Item1 == Convert.ToHexString(certId.SerialNumber));
        var certificateItem = kvp.Value;
        if (certificateItem == null)
        {
            return Task.FromResult<(CertId, CertificateStatus, RevokedInfo?)>((
                certId, CertificateStatus.Unknown, null));
        }

        var result = certificateItem.IsRevoked
            ? (certId, CertificateStatus.Revoked,
               (RevokedInfo?)new RevokedInfo(certificateItem.RevocationDate!.Value, certificateItem.RevocationReason))
            : (certId, CertificateStatus.Good, (RevokedInfo?)null);
        return Task.FromResult(result);
    }

    /// <inheritdoc />
    public IAsyncEnumerable<CertificateItemInfo> GetInventory(
        int page = 0,
        int pageSize = 100,
        CancellationToken cancellationToken = default)
    {
        return _certificates
            .OrderBy(x => x.Key.Item1, StringComparer.Ordinal)
            .Skip(page * pageSize)
            .Take(pageSize)
            .Select(x => x.Value.AsInfo())
            .ToAsyncEnumerable();
    }

    /// <inheritdoc />
    public IAsyncEnumerable<X509Certificate2> GetCertificatesById(
        string? issuingProfile,
        CancellationToken cancellationToken,
        params IEnumerable<ReadOnlyMemory<byte>> ids)
    {
        var idSet = new HashSet<string>(ids.Select(i => Convert.ToHexString(i.Span)));
        return _certificates
            .Where(x => idSet.Contains(x.Key.Item1) &&
                string.Equals(x.Key.Item2, issuingProfile, StringComparison.Ordinal))
            .OrderBy(x => x.Key.Item1, StringComparer.Ordinal)
            .Select(x => X509Certificate2.CreateFromPem(x.Value.PublicKeyPem))
            .ToAsyncEnumerable();
    }

    /// <inheritdoc />
    public IAsyncEnumerable<X509Certificate2> GetCertificatesByThumbprint(
        IEnumerable<ReadOnlyMemory<char>> thumbprint,
        CancellationToken cancellationToken = default)
    {
        var thumbprintSet = new HashSet<string>(thumbprint.Select(t => t.ToString()),
            StringComparer.OrdinalIgnoreCase);
        // The dictionary is keyed by serial number (AddCertificate); the thumbprint lives in the
        // item. Comparing against the key found nothing, ever.
        return _certificates
            .Where(x => thumbprintSet.Contains(x.Value.Thumbprint))
            .OrderBy(x => x.Key.Item1, StringComparer.Ordinal)
            .Select(x => X509Certificate2.CreateFromPem(x.Value.PublicKeyPem))
            .ToAsyncEnumerable();
    }
}
