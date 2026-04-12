namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

/// <summary>
/// Persists the ACME site certificate in the operating system's X.509 certificate store.
/// The certificate is stored with its private key, making it available to the server application
/// across restarts without requiring a separate key file.
/// </summary>
/// <remarks>
/// <para>
/// This strategy works across macOS, Linux, and Windows:
/// <list type="bullet">
///   <item><term>Windows</term><description>Stores in the Windows Certificate Store (CryptoAPI / CNG).</description></item>
///   <item><term>macOS</term><description>Stores in the user's Keychain.</description></item>
///   <item><term>Linux</term><description>Stores in the .NET per-user X.509 store directory
///   (<c>~/.dotnet/corefx/cryptography/x509stores/</c>).</description></item>
/// </list>
/// </para>
/// <para>
/// Account certificates (ACME private keys) are not stored in the certificate store; returning
/// <see langword="null"/> from <see cref="RetrieveAccountCertificate"/> causes the
/// <see cref="PersistenceService"/> to fall back to other registered strategies or request a new
/// account key from the ACME server.
/// </para>
/// </remarks>
public sealed class CertificateStorePersistenceStrategy : ICertificatePersistenceStrategy
{
    private readonly string _subjectName;
    private readonly StoreName _storeName;
    private readonly StoreLocation _storeLocation;

    /// <summary>
    /// Initialises a new instance of <see cref="CertificateStorePersistenceStrategy"/>.
    /// </summary>
    /// <param name="subjectName">
    /// The subject (CN) or domain name used to identify the certificate inside the store.
    /// This must match (or be a substring of) the Subject of the ACME certificate, e.g.
    /// <c>"example.com"</c>.
    /// </param>
    /// <param name="storeName">
    /// The certificate store name. Defaults to <see cref="StoreName.My"/> (the personal store).
    /// </param>
    /// <param name="storeLocation">
    /// The certificate store location. Defaults to <see cref="StoreLocation.CurrentUser"/>,
    /// which works without elevated privileges on all supported platforms.
    /// </param>
    public CertificateStorePersistenceStrategy(
        string subjectName,
        StoreName storeName = StoreName.My,
        StoreLocation storeLocation = StoreLocation.CurrentUser)
    {
        if (string.IsNullOrWhiteSpace(subjectName))
        {
            throw new ArgumentException("A non-empty subject name is required to identify the certificate in the store.", nameof(subjectName));
        }

        _subjectName = subjectName;
        _storeName = storeName;
        _storeLocation = storeLocation;
    }

    /// <inheritdoc />
    /// <remarks>
    /// For <see cref="CertificateType.Site"/>, the DER bytes are loaded into an
    /// <see cref="X509Certificate2"/> and stored in the OS certificate store.
    /// Because the DER bytes do not contain a private key, prefer the
    /// <see cref="PersistSiteCertificate(X509Certificate2)"/> overload when possible.
    /// For <see cref="CertificateType.Account"/>, the operation is a no-op.
    /// </remarks>
    public Task Persist(CertificateType persistenceType, byte[] certificate)
    {
        if (persistenceType != CertificateType.Site)
        {
            // Account PEM keys are not stored in the OS certificate store.
            return Task.CompletedTask;
        }

        using var cert = X509CertificateLoader.LoadCertificate(certificate);
        StoreCertificate(cert);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Stores the full certificate (including any associated private key) in the OS certificate
    /// store, replacing any previously stored certificate whose subject matches
    /// <see cref="_subjectName"/>.
    /// </remarks>
    public Task PersistSiteCertificate(X509Certificate2 certificate)
    {
        StoreCertificate(certificate);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Always returns <see langword="null"/>. Account keys are not stored in the OS certificate
    /// store; a complementary persistence strategy (e.g.
    /// <see cref="FileCertificatePersistenceStrategy"/> or
    /// <see cref="InMemoryCertificatePersistenceStrategy"/>) should be registered alongside this
    /// one to handle account key persistence.
    /// </remarks>
    public Task<byte[]?> RetrieveAccountCertificate()
        => Task.FromResult<byte[]?>(null);

    /// <inheritdoc />
    /// <remarks>
    /// Searches the OS certificate store for a certificate whose subject contains
    /// <see cref="_subjectName"/> and that has an accessible private key. When multiple matches
    /// exist, the one with the latest expiry date is returned.
    /// </remarks>
    public Task<X509Certificate2?> RetrieveSiteCertificate()
    {
        try
        {
            using var store = new X509Store(_storeName, _storeLocation);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

            var match = store.Certificates
                .Find(X509FindType.FindBySubjectName, _subjectName, validOnly: false)
                .Where(c => c.HasPrivateKey)
                .OrderByDescending(c => c.NotAfter)
                .FirstOrDefault();

            return Task.FromResult(match);
        }
        catch (CryptographicException)
        {
            // The store does not exist yet (can happen on first run with a custom store name).
            return Task.FromResult<X509Certificate2?>(null);
        }
    }

    private void StoreCertificate(X509Certificate2 certificate)
    {
        using var store = new X509Store(_storeName, _storeLocation);
        store.Open(OpenFlags.ReadWrite);

        // Remove any previously stored certificates with the same subject to avoid accumulation
        // of stale entries across renewal cycles.
        var existing = store.Certificates
            .Find(X509FindType.FindBySubjectName, _subjectName, validOnly: false);

        foreach (var old in existing)
        {
            store.Remove(old);
        }

        store.Add(certificate);
    }
}


