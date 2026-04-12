namespace OpenCertServer.Tpm;

using System.Linq;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Persists and retrieves CA public certificates using the OS certificate store
/// (<see cref="X509Store"/>).  The private key lives in the TPM; only the public
/// certificate is written here.  No elevated permissions are required when
/// <see cref="StoreLocation.CurrentUser"/> is used.
/// </summary>
public sealed class TpmCaCertificateStore
{
    private const string SubjectPrefix = "tpm-ca-";

    private readonly System.Security.Cryptography.X509Certificates.StoreName _storeName;
    private readonly StoreLocation _storeLocation;

    /// <summary>
    /// Creates a store accessor using the specified OS certificate store.
    /// </summary>
    public TpmCaCertificateStore(
        System.Security.Cryptography.X509Certificates.StoreName storeName,
        StoreLocation storeLocation)
    {
        _storeName = storeName;
        _storeLocation = storeLocation;
    }

    /// <summary>
    /// Loads the most recently issued (by NotAfter) CA certificate for
    /// <paramref name="profileName"/> from the store, or <c>null</c> if none is found.
    /// </summary>
    public X509Certificate2? LoadCertificate(string profileName)
    {
        using var store = new X509Store(_storeName, _storeLocation);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        return store.Certificates
            .Find(X509FindType.FindBySubjectName, SubjectTag(profileName), validOnly: false)
            .Cast<X509Certificate2>()
            .OrderByDescending(c => c.NotAfter)
            .FirstOrDefault();
    }

    /// <summary>
    /// Stores a public-only copy of <paramref name="certificate"/> in the OS certificate store,
    /// replacing any older certificate with the same profile tag.
    /// </summary>
    public void StoreCertificate(string profileName, X509Certificate2 certificate)
    {
        // Export and re-import as DER to strip any attached private key blob.
        var publicOnly = X509Certificate2.CreateFromPem(certificate.ExportCertificatePem());

        using var store = new X509Store(_storeName, _storeLocation);
        store.Open(OpenFlags.ReadWrite);

        // Remove stale entries for this profile first.
        var stale = store.Certificates
            .Find(X509FindType.FindBySubjectName, SubjectTag(profileName), validOnly: false);
        foreach (X509Certificate2 old in stale)
        {
            store.Remove(old);
        }

        store.Add(publicOnly);
    }

    private static string SubjectTag(string profileName) => $"{SubjectPrefix}{profileName}";
}

