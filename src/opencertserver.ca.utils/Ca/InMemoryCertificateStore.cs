namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.Ocsp;

public class InMemoryCertificateStore : IStoreCertificates
{
    private readonly Dictionary<string, CertificateItem> _certificates = new();

    public Task AddCertificate(X509Certificate2 certificate)
    {
        _certificates.Add(certificate.GetSerialNumberString(), CertificateItem.FromX509Certificate2(certificate));
        return Task.CompletedTask;
    }

    public Task<bool> RemoveCertificate(string serialNumber, X509RevocationReason reason)
    {
        if (!_certificates.TryGetValue(serialNumber, out var certificateItem))
        {
            return Task.FromResult(false);
        }

        certificateItem.RevocationDate = DateTimeOffset.UtcNow;
        certificateItem.RevocationReason = reason;
        return Task.FromResult(true);
    }

    public IAsyncEnumerable<CertificateItemInfo> GetRevocationList(int page = 0, int pageSize = 100)
    {
        return _certificates
            .OrderBy(x => x.Key)
            .Where(x => x.Value.IsRevoked)
            .Skip(page * pageSize)
            .Take(pageSize)
            .Select(x => x.Value.AsInfo())
            .ToAsyncEnumerable();
    }

    public async Task<(CertId, CertificateStatus, RevokedInfo?)> GetCertificateStatus(CertId certId)
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

    public IAsyncEnumerable<CertificateItemInfo> GetInventory(int page = 0, int pageSize = 100)
    {
        return _certificates
            .OrderBy(x => x.Key)
            .Skip(page * pageSize)
            .Take(pageSize)
            .Select(x => x.Value.AsInfo())
            .ToAsyncEnumerable();
    }

    public IAsyncEnumerable<X509Certificate2> GetCertificatesById(params IEnumerable<ReadOnlyMemory<byte>> ids)
    {
        var idStrings = ids.Select(i => Convert.ToHexString(i.Span));
        return _certificates
            .Where(x => idStrings.Contains(x.Key))
            .OrderBy(x => x.Key)
            .Select(x => X509Certificate2.CreateFromPem(x.Value.PublicKeyPem))
            .ToAsyncEnumerable();
    }

    public IAsyncEnumerable<X509Certificate2> GetCertificatesByThumbprint(IEnumerable<ReadOnlyMemory<char>> thumbprint)
    {
        var thumbprintStrings = thumbprint.ToArray();
        return _certificates
            .Where(x => thumbprintStrings.Any(t => t.Equals(x.Key.AsMemory())))
            .OrderBy(x => x.Key)
            .Select(x => X509Certificate2.CreateFromPem(x.Value.PublicKeyPem))
            .ToAsyncEnumerable();
    }
}
