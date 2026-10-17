using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Est.Server.TrustAnchor;

/// <summary>
/// Explicit client trust anchors and intermediate certificates used by EST certificate authentication.
/// </summary>
public sealed class EstTrustAnchorOptions
{
    /// <summary>
    /// Gets the certificates that may terminate a client certificate chain.
    /// </summary>
    public X509Certificate2Collection TrustAnchors { get; } = [];

    /// <summary>
    /// Gets additional certificates that may help build a client certificate chain.
    /// These certificates are not trusted as chain roots.
    /// </summary>
    public X509Certificate2Collection AdditionalChainCertificates { get; } = [];
}
