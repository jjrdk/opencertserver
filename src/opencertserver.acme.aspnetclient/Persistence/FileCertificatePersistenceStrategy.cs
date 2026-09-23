namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

public sealed class FileCertificatePersistenceStrategy : ICertificatePersistenceStrategy
{
    private const string ServerPfx = "server.pfx";
    private const string ServerCrt = "server.crt";
    private const string ServerKey = "server.key";
    private const string LeavesDir = "leaves";
    private const string ChainsDir = "chains";
    private const string KeysDir = "keys";
    private readonly string _root;

    public FileCertificatePersistenceStrategy(string relativeFilePath)
    {
        _root = relativeFilePath;
        Directory.CreateDirectory(_root);
    }

    public Task Persist(CertificateType persistenceType, byte[] certificate)
    {
        return File.WriteAllBytesAsync(GetCertificatePath(persistenceType), certificate);
    }

    public async Task PersistSiteCertificate(X509Certificate2 certificate)
    {
        await File.WriteAllBytesAsync(GetCertificatePath(CertificateType.Site), certificate.RawData)
            .ConfigureAwait(false);
    }

    public async Task PersistSiteCertificate(X509Certificate2 certificate, string routeId)
    {
        var leafDir = GetDir(routeId, LeavesDir);
        var chainDir = GetDir(routeId, ChainsDir);
        var keyDir = GetDir(routeId, KeysDir);

        if (certificate.HasPrivateKey)
        {
            var pfx = certificate.Export(X509ContentType.Pkcs12, string.Empty);
            await File.WriteAllBytesAsync(Path.Combine(leafDir, ServerPfx), pfx).ConfigureAwait(false);
        }

        await File.WriteAllBytesAsync(Path.Combine(leafDir, ServerCrt), certificate.RawData).ConfigureAwait(false);

        // Leaf-only fallback: when no issuers are available the leaf PEM is written to the
        // chains directory so the artifact path always exists. The real issuer chain is written
        // by <see cref="PersistSiteCertificateChain"/>.
        var chainPem = certificate.ExportCertificatePem();
        await File.WriteAllBytesAsync(Path.Combine(chainDir, ServerCrt), Encoding.UTF8.GetBytes(chainPem))
            .ConfigureAwait(false);

        var keyPem = ToPrivateKeyPem(certificate);
        if (keyPem != null)
        {
            await File.WriteAllBytesAsync(Path.Combine(keyDir, ServerKey), Encoding.UTF8.GetBytes(keyPem))
                .ConfigureAwait(false);
        }
    }

    public async Task PersistSiteCertificateChain(X509Certificate2Collection chain, string routeId)
    {
        var leafDir = GetDir(routeId, LeavesDir);
        var chainDir = GetDir(routeId, ChainsDir);
        var keyDir = GetDir(routeId, KeysDir);

        var leaf = chain[0];
        var issuers = chain.Count > 1 ? chain.Skip(1) : [];

        var tasks = new List<Task>
        {
            File.WriteAllBytesAsync(Path.Combine(leafDir, ServerCrt), leaf.RawData)
        };

        if (leaf.HasPrivateKey)
        {
            var pfx = leaf.Export(X509ContentType.Pkcs12, string.Empty);
            tasks.Add(File.WriteAllBytesAsync(Path.Combine(leafDir, ServerPfx), pfx));

            var keyPem = ToPrivateKeyPem(leaf);
            if (keyPem != null)
            {
                tasks.Add(File.WriteAllBytesAsync(Path.Combine(keyDir, ServerKey), Encoding.UTF8.GetBytes(keyPem)));
            }
        }

        var chainPem = string.Concat(issuers.Select(c => $"{c.ExportCertificatePem()}\n"));
        if (!string.IsNullOrWhiteSpace(chainPem))
        {
            tasks.Add(File.WriteAllBytesAsync(Path.Combine(chainDir, ServerCrt), Encoding.UTF8.GetBytes(chainPem)));
        }

        await Task.WhenAll(tasks);
    }

    public async Task<byte[]?> RetrieveAccountCertificate()
    {
        var bytes = await ReadFile(CertificateType.Account).ConfigureAwait(false);
        return bytes;
    }

    public async Task<X509Certificate2?> RetrieveSiteCertificate()
    {
        var bytes = await ReadFile(CertificateType.Site).ConfigureAwait(false);
        return bytes == null ? null : X509CertificateLoader.LoadCertificate(bytes);
    }

    public async Task<X509Certificate2?> RetrieveSiteCertificate(string routeId)
    {
        var pfxPath = Path.Combine(_root, routeId, LeavesDir, ServerPfx);
        if (File.Exists(pfxPath))
        {
            var pfx = await File.ReadAllBytesAsync(pfxPath).ConfigureAwait(false);
            return X509CertificateLoader.LoadPkcs12(pfx, null);
        }

        var leafPath = Path.Combine(_root, routeId, LeavesDir, ServerCrt);
        if (!File.Exists(leafPath))
        {
            return null;
        }

        // Defensive: if a private key was persisted separately (e.g. from a previous run where
        // the PKCS12 was never written because HasPrivateKey was false), reconstruct the full
        // certificate by combining the PEM cert with the PEM key so Kestrel receives a certificate
        // that carries its private key.
        var keyPath = Path.Combine(_root, routeId, KeysDir, ServerKey);
        if (File.Exists(keyPath))
        {
            var certPem = await File.ReadAllTextAsync(leafPath).ConfigureAwait(false);
            var keyPem = await File.ReadAllTextAsync(keyPath).ConfigureAwait(false);
            return X509Certificate2.CreateFromPem(certPem, keyPem);
        }

        var bytes = await File.ReadAllBytesAsync(leafPath).ConfigureAwait(false);
        return X509CertificateLoader.LoadCertificate(bytes);
    }

    public async Task<string?> GetPersistedRouteKey(string routeId, CancellationToken cancellationToken = default)
    {
        var path = Path.Combine(_root, routeId, KeysDir, ServerKey);
        if (!File.Exists(path))
        {
            return null;
        }

        return await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
    }

    public async Task PersistRouteKey(string routeId, string keyPem, CancellationToken cancellationToken = default)
    {
        var dir = GetDir(routeId, KeysDir);
        await File.WriteAllTextAsync(Path.Combine(dir, ServerKey), keyPem, cancellationToken).ConfigureAwait(false);
    }

    private static string? ToPrivateKeyPem(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
        {
            return null;
        }

        var rsa = certificate.GetRSAPrivateKey();
        if (rsa != null)
        {
            return rsa.ExportRSAPrivateKeyPem();
        }

        var ecdsa = certificate.GetECDsaPrivateKey();
        return ecdsa?.ExportECPrivateKeyPem();
    }

    private string GetCertificatePath(CertificateType persistenceType)
    {
        return $"{_root}_{persistenceType}";
    }

    private string GetDir(string routeId, string subDir)
    {
        var path = Path.Combine(_root, routeId, subDir);
        Directory.CreateDirectory(path);
        return path;
    }

    private async Task<byte[]?> ReadFile(CertificateType persistenceType)
    {
        return !File.Exists(GetCertificatePath(persistenceType))
            ? null
            : await File.ReadAllBytesAsync(GetCertificatePath(persistenceType)).ConfigureAwait(false);
    }
}
