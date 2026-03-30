namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Provides an in-memory implementation of <see cref="IStoreCertificates"/> for certificate inventory and revocation tracking.
/// </summary>
public class InMemoryCertificateStore : IStoreCertificates
{
    /// <summary>
    /// Executes the new operation.
    /// </summary>
    private readonly Dictionary<string, CertificateItem> _certificates = new();

    /// <inheritdoc />
    public Task AddCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default)
    {
        _certificates.Add(certificate.GetSerialNumberString(), CertificateItem.FromX509Certificate2(certificate));
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> RemoveCertificate(
        string serialNumber,
        X509RevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        if (!_certificates.TryGetValue(serialNumber, out var certificateItem))
        {
            return Task.FromResult(false);
        }

        certificateItem.RevocationDate = DateTimeOffset.UtcNow;
        certificateItem.RevocationReason = reason;
        return Task.FromResult(true);
    }

    /// <inheritdoc />
    public IAsyncEnumerable<CertificateItemInfo> GetRevocationList(
        int page = 0,
        int pageSize = 100,
        CancellationToken cancellationToken = default)
    {
        return _certificates
            .OrderBy(x => x.Key)
            .Where(x => x.Value.IsRevoked)
            .Skip(page * pageSize)
            .Take(pageSize)
            .Select(x => x.Value.AsInfo())
            .ToAsyncEnumerable();
    }

    /// <inheritdoc />
    public async Task<(CertId, CertificateStatus, RevokedInfo?)> GetCertificateStatus(
        CertId certId,
        CancellationToken cancellationToken = default)
    {
        await Task.Yield();
        var found = _certificates.TryGetValue(Convert.ToHexString(certId.SerialNumber), out var certificateItem);
        if (!found)
        {
            return (certId, CertificateStatus.Unknown, null);
        }

        return certificateItem!.IsRevoked
            ? (certId, CertificateStatus.Revoked,
               new RevokedInfo(certificateItem.RevocationDate!.Value, certificateItem.RevocationReason))
            : (certId, CertificateStatus.Good, null);
    }

    /// <inheritdoc />
    public IAsyncEnumerable<CertificateItemInfo> GetInventory(
        int page = 0,
        int pageSize = 100,
        CancellationToken cancellationToken = default)
    {
        return _certificates
            .OrderBy(x => x.Key)
            .Skip(page * pageSize)
            .Take(pageSize)
            .Select(x => x.Value.AsInfo())
            .ToAsyncEnumerable();
    }

    /// <inheritdoc />
    public IAsyncEnumerable<X509Certificate2> GetCertificatesById(
        CancellationToken cancellationToken,
        params IEnumerable<ReadOnlyMemory<byte>> ids)
    {
        var idStrings = ids.Select(i => Convert.ToHexString(i.Span));
        return _certificates
            .Where(x => idStrings.Contains(x.Key))
            .OrderBy(x => x.Key)
            .Select(x => X509Certificate2.CreateFromPem(x.Value.PublicKeyPem))
            .ToAsyncEnumerable();
    }

    /// <inheritdoc />
    public IAsyncEnumerable<X509Certificate2> GetCertificatesByThumbprint(
        IEnumerable<ReadOnlyMemory<char>> thumbprint,
        CancellationToken cancellationToken = default)
    {
        var thumbprintStrings = thumbprint.ToArray();
        return _certificates
            .Where(x => thumbprintStrings.Any(t => t.Equals(x.Key.AsMemory())))
            .OrderBy(x => x.Key)
            .Select(x => X509Certificate2.CreateFromPem(x.Value.PublicKeyPem))
            .ToAsyncEnumerable();
    }
}
