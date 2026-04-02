namespace OpenCertServer.Est.Client;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Represents EST trust material retrieved during bootstrap that requires out-of-band authorization.
/// </summary>
public sealed class EstBootstrapTrust
{
    internal EstBootstrapTrust(Uri sourceUri, X509Certificate2Collection certificates)
    {
        SourceUri = sourceUri;
        var collection = new X509Certificate2Collection();
        collection.AddRange(certificates);
        Certificates = collection;
        Fingerprints = certificates
            .Select(certificate => Convert.ToHexStringLower(SHA256.HashData(certificate.RawData)))
            .ToArray();
    }

    /// <summary>
    /// Gets the EST URI that returned the bootstrap trust material.
    /// </summary>
    public Uri SourceUri { get; }

    /// <summary>
    /// Gets the certificates returned during bootstrap.
    /// </summary>
    public X509Certificate2Collection Certificates { get; }

    /// <summary>
    /// Gets the SHA-256 fingerprints for the returned certificates.
    /// </summary>
    public IReadOnlyList<string> Fingerprints { get; }
}



