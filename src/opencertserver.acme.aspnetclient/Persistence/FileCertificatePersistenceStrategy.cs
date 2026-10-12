namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System.IO;
using System.Linq;
using System.Security.Cryptography;
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

    // Marker lines prefixed to the encrypted PKCS#8 PEM so the decryption path knows the original key type.
    private const string RsaKeyTypeMarker = "KEYTYPE:RSA\n";
    private const string EcKeyTypeMarker = "KEYTYPE:EC\n";

    // PBKDF2-SHA256 with AES-256-CBC at 600 000 iterations (OWASP 2023 recommendation).
    private static readonly PbeParameters PbeParams =
        new(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 600_000);

    private readonly string _root;
    private readonly string _password;

    /// <summary>
    /// Creates a file-backed certificate persistence strategy that encrypts all private-key
    /// material at rest using <paramref name="password"/>.
    /// </summary>
    /// <param name="relativeFilePath">Root directory for persisted files.</param>
    /// <param name="password">
    /// Non-empty password used to encrypt PFX containers and private-key PEM files.
    /// This must match across restarts; changing the password requires deleting the persisted
    /// files and performing a new ACME issuance.
    /// </param>
    /// <exception cref="ArgumentException">Thrown when <paramref name="password"/> is null or empty.</exception>
    public FileCertificatePersistenceStrategy(string relativeFilePath, string password)
    {
        ArgumentException.ThrowIfNullOrEmpty(password, nameof(password));
        _root = relativeFilePath;
        _password = password;
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
            var pfx = certificate.Export(X509ContentType.Pkcs12, _password);
            await File.WriteAllBytesAsync(Path.Combine(leafDir, ServerPfx), pfx).ConfigureAwait(false);
        }

        await File.WriteAllBytesAsync(Path.Combine(leafDir, ServerCrt), certificate.RawData).ConfigureAwait(false);

        // Leaf-only fallback: when no issuers are available the leaf PEM is written to the
        // chains directory so the artifact path always exists. The real issuer chain is written
        // by <see cref="PersistSiteCertificateChain"/>.
        var chainPem = certificate.ExportCertificatePem();
        await File.WriteAllBytesAsync(Path.Combine(chainDir, ServerCrt), Encoding.UTF8.GetBytes(chainPem))
            .ConfigureAwait(false);

        var encryptedKeyPem = ToEncryptedPrivateKeyPem(certificate);
        if (encryptedKeyPem != null)
        {
            await File.WriteAllBytesAsync(Path.Combine(keyDir, ServerKey), Encoding.UTF8.GetBytes(encryptedKeyPem))
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
            var pfx = leaf.Export(X509ContentType.Pkcs12, _password);
            tasks.Add(File.WriteAllBytesAsync(Path.Combine(leafDir, ServerPfx), pfx));

            var encryptedKeyPem = ToEncryptedPrivateKeyPem(leaf);
            if (encryptedKeyPem != null)
            {
                tasks.Add(File.WriteAllBytesAsync(Path.Combine(keyDir, ServerKey), Encoding.UTF8.GetBytes(encryptedKeyPem)));
            }
        }

        var chainPem = string.Concat(issuers.Select(c => $"{c.ExportCertificatePem()}\n"));
        if (!string.IsNullOrWhiteSpace(chainPem))
        {
            tasks.Add(File.WriteAllBytesAsync(Path.Combine(chainDir, ServerCrt), Encoding.UTF8.GetBytes(chainPem)));
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
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
            return X509CertificateLoader.LoadPkcs12(pfx, _password);
        }

        var leafPath = Path.Combine(_root, routeId, LeavesDir, ServerCrt);
        if (!File.Exists(leafPath))
        {
            return null;
        }

        // Defensive: if a private key was persisted separately (e.g. from a previous run where
        // the PKCS12 was never written because HasPrivateKey was false), reconstruct the full
        // certificate by combining the PEM cert with the encrypted PEM key.
        var keyPath = Path.Combine(_root, routeId, KeysDir, ServerKey);
        if (File.Exists(keyPath))
        {
            var certPem = await File.ReadAllTextAsync(leafPath).ConfigureAwait(false);
            var storedKeyContent = await File.ReadAllTextAsync(keyPath).ConfigureAwait(false);
            var encryptedKeyPem = StripKeyTypeMarker(storedKeyContent);
            return X509Certificate2.CreateFromEncryptedPem(certPem, encryptedKeyPem, _password);
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

        var storedContent = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
        return DecryptKeyPem(storedContent);
    }

    public async Task PersistRouteKey(string routeId, string keyPem, CancellationToken cancellationToken = default)
    {
        var dir = GetDir(routeId, KeysDir);
        var encryptedContent = EncryptKeyPem(keyPem);
        await File.WriteAllTextAsync(Path.Combine(dir, ServerKey), encryptedContent, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Exports the certificate's private key as an encrypted PKCS#8 PEM prefixed with a key-type
    /// marker line, or <c>null</c> when the certificate has no private key.
    /// </summary>
    private string? ToEncryptedPrivateKeyPem(X509Certificate2 certificate)
    {
        if (!certificate.HasPrivateKey)
        {
            return null;
        }

        using var rsa = certificate.GetRSAPrivateKey();
        if (rsa != null)
        {
            return RsaKeyTypeMarker + rsa.ExportEncryptedPkcs8PrivateKeyPem(_password, PbeParams);
        }

        using var ecdsa = certificate.GetECDsaPrivateKey();
        if (ecdsa != null)
        {
            return EcKeyTypeMarker + ecdsa.ExportEncryptedPkcs8PrivateKeyPem(_password, PbeParams);
        }

        return null;
    }

    /// <summary>
    /// Encrypts a plaintext private-key PEM (PKCS#1 RSA or explicit EC format as produced by
    /// <c>CertesSlim</c>) into an encrypted PKCS#8 PEM prefixed with a key-type marker line.
    /// </summary>
    private string EncryptKeyPem(string plainKeyPem)
    {
        if (plainKeyPem.Contains("RSA PRIVATE KEY", StringComparison.Ordinal))
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(plainKeyPem);
            return RsaKeyTypeMarker + rsa.ExportEncryptedPkcs8PrivateKeyPem(_password, PbeParams);
        }

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(plainKeyPem);
        return EcKeyTypeMarker + ecdsa.ExportEncryptedPkcs8PrivateKeyPem(_password, PbeParams);
    }

    /// <summary>
    /// Decrypts a stored key file produced by <see cref="EncryptKeyPem"/> or
    /// <see cref="ToEncryptedPrivateKeyPem"/> and returns the private key in the original
    /// plaintext format expected by <c>KeyFactory.FromPem</c> (PKCS#1 RSA or explicit EC).
    /// </summary>
    private string DecryptKeyPem(string storedContent)
    {
        if (storedContent.StartsWith(RsaKeyTypeMarker, StringComparison.Ordinal))
        {
            var encryptedPem = storedContent[RsaKeyTypeMarker.Length..];
            using var rsa = RSA.Create();
            rsa.ImportFromEncryptedPem(encryptedPem, _password);
            return rsa.ExportRSAPrivateKeyPem();
        }

        if (storedContent.StartsWith(EcKeyTypeMarker, StringComparison.Ordinal))
        {
            var encryptedPem = storedContent[EcKeyTypeMarker.Length..];
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportFromEncryptedPem(encryptedPem, _password);
            return ecdsa.ExportECPrivateKeyPem();
        }

        throw new InvalidOperationException(
            "The key file is in an unrecognised format. It may have been written by an older version of " +
            "OpenCertServer that did not encrypt private keys. Delete the persisted certificates and let " +
            "the ACME renewal service re-issue to resolve this.");
    }

    /// <summary>
    /// Strips the leading key-type marker line (if present) and returns just the PEM content,
    /// ready for <see cref="X509Certificate2.CreateFromEncryptedPem"/>.
    /// </summary>
    private static string StripKeyTypeMarker(string storedContent)
    {
        if (storedContent.StartsWith(RsaKeyTypeMarker, StringComparison.Ordinal))
        {
            return storedContent[RsaKeyTypeMarker.Length..];
        }

        if (storedContent.StartsWith(EcKeyTypeMarker, StringComparison.Ordinal))
        {
            return storedContent[EcKeyTypeMarker.Length..];
        }

        return storedContent;
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
