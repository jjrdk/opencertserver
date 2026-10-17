using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Est.Server.TrustAnchor;

/// <summary>
/// Supplies explicit trust anchors used when authenticating EST client certificates.
/// </summary>
public interface IEstTrustAnchorProvider
{
    /// <summary>
    /// Gets the explicitly trusted client certificate roots.
    /// </summary>
    IReadOnlyCollection<X509Certificate2> TrustAnchors { get; }

    /// <summary>
    /// Gets certificates available to chain building that are not themselves trust anchors.
    /// </summary>
    IReadOnlyCollection<X509Certificate2> AdditionalChainCertificates { get; }
}