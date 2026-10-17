using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Est.Server.TrustAnchor;

internal sealed class EmptyEstTrustAnchorProvider : IEstTrustAnchorProvider
{
    public static readonly EmptyEstTrustAnchorProvider Instance = new();

    private EmptyEstTrustAnchorProvider()
    {
    }

    public IReadOnlyCollection<X509Certificate2> TrustAnchors { get; } = Array.Empty<X509Certificate2>();

    public IReadOnlyCollection<X509Certificate2> AdditionalChainCertificates { get; } =
        Array.Empty<X509Certificate2>();
}
