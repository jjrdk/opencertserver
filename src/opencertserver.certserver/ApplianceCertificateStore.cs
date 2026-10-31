namespace OpenCertServer.CertServer;

using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Serialization;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;

internal sealed class ApplianceCertificateStore : IStoreCertificates, IDisposable
{
    private readonly string _path;
    private readonly FileStream _lease;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private volatile CertificateItem[] _certificates;

    public ApplianceCertificateStore(string directory)
    {
        Directory.CreateDirectory(directory);
        _path = Path.Combine(directory, "certificates.json");
        _lease = new FileStream(Path.Combine(directory, "certificates.lock"),
            FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        try
        {
            if (File.Exists(_path))
            {
                var store = JsonSerializer.Deserialize(File.ReadAllText(_path),
                        ApplianceStoreJsonContext.Default.ApplianceStoreDocument)
                 ?? throw new InvalidDataException("The certificate store is empty.");
                if (store.Version != 1)
                {
                    throw new InvalidDataException($"Unsupported certificate store version {store.Version}.");
                }

                _certificates = store.Certificates;
            }
            else
            {
                _certificates = [];
                Save(_certificates);
            }
        }
        catch
        {
            _lease.Dispose();
            throw;
        }
    }

    public async Task AddCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var item = CertificateItem.FromX509Certificate2(certificate);
            if (_certificates.Any(existing => existing.SerialNumber == item.SerialNumber))
            {
                throw new InvalidOperationException("The certificate serial number is already stored.");
            }

            var updated = _certificates.Append(item).ToArray();
            Save(updated);
            _certificates = updated;
        }
        finally
        {
            _gate.Release();
        }
    }

    public async Task<bool> RemoveCertificate(
        string serialNumber,
        X509RevocationReason reason,
        CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken);
        try
        {
            var updated = _certificates.ToArray();
            var index = Array.FindIndex(updated, item =>
                string.Equals(item.SerialNumber, serialNumber, StringComparison.OrdinalIgnoreCase));
            if (index < 0)
            {
                return false;
            }

            // Never mutate the live snapshot before its durable replacement succeeds.
            using var certificate = X509Certificate2.CreateFromPem(updated[index].PublicKeyPem);
            updated[index] = CertificateItem.FromX509Certificate2(certificate);
            updated[index].RevocationDate = _certificates[index].RevocationDate ?? DateTimeOffset.UtcNow;
            updated[index].RevocationReason = reason;
            Save(updated);
            _certificates = updated;
            return true;
        }
        finally
        {
            _gate.Release();
        }
    }

    public IAsyncEnumerable<CertificateItemInfo> GetInventory(
        int page = 0,
        int pageSize = 100,
        CancellationToken cancellationToken = default) =>
        _certificates.OrderBy(item => item.SerialNumber).Skip(page * pageSize).Take(pageSize)
            .Select(item => item.AsInfo()).ToAsyncEnumerable();

    public IAsyncEnumerable<CertificateItemInfo> GetRevocationList(
        int page = 0,
        int pageSize = 100,
        CancellationToken cancellationToken = default) =>
        _certificates.Where(item => item.IsRevoked).OrderBy(item => item.SerialNumber)
            .Skip(page * pageSize).Take(pageSize).Select(item => item.AsInfo()).ToAsyncEnumerable();

    public Task<(CertId, CertificateStatus, RevokedInfo?)> GetCertificateStatus(
        CertId certId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var item = _certificates.FirstOrDefault(certificate =>
            certificate.SerialNumber == Convert.ToHexString(certId.SerialNumber));
        return Task.FromResult<(CertId, CertificateStatus, RevokedInfo?)>(item is null
            ? (certId, CertificateStatus.Unknown, null)
            : item.IsRevoked
                ? (certId, CertificateStatus.Revoked,
                   new RevokedInfo(item.RevocationDate!.Value, item.RevocationReason))
                : (certId, CertificateStatus.Good, null));
    }

    public IAsyncEnumerable<X509Certificate2> GetCertificatesById(
        CancellationToken cancellationToken,
        params IEnumerable<ReadOnlyMemory<byte>> ids)
    {
        var serials = ids.Select(id => Convert.ToHexString(id.Span)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return ReadCertificates(_certificates.Where(item => serials.Contains(item.SerialNumber)), cancellationToken);
    }

    public IAsyncEnumerable<X509Certificate2> GetCertificatesByThumbprint(
        IEnumerable<ReadOnlyMemory<char>> thumbprint,
        CancellationToken cancellationToken = default)
    {
        var values = thumbprint.Select(value => value.ToString()).ToHashSet(StringComparer.OrdinalIgnoreCase);
        return ReadCertificates(_certificates.Where(item => values.Contains(item.Thumbprint)), cancellationToken);
    }

    private static async IAsyncEnumerable<X509Certificate2> ReadCertificates(
        IEnumerable<CertificateItem> items,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var item in items)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return X509Certificate2.CreateFromPem(item.PublicKeyPem);
        }

        await Task.CompletedTask;
    }

    private void Save(CertificateItem[] certificates)
    {
        var temporary = _path + ".tmp";
        try
        {
            using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                JsonSerializer.Serialize(stream,
                    new ApplianceStoreDocument { Version = 1, Certificates = certificates },
                    ApplianceStoreJsonContext.Default.ApplianceStoreDocument);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, _path, overwrite: true);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    public void Dispose()
    {
        _lease.Dispose();
        _gate.Dispose();
    }
}

internal sealed class ApplianceStoreDocument
{
    public required int Version { get; set; }
    public required CertificateItem[] Certificates { get; set; }
}

[JsonSerializable(typeof(ApplianceStoreDocument))]
internal partial class ApplianceStoreJsonContext : JsonSerializerContext;
