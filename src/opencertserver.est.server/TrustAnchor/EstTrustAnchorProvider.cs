using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;

namespace OpenCertServer.Est.Server.TrustAnchor;

internal sealed class EstTrustAnchorProvider : IEstTrustAnchorProvider
{
    public EstTrustAnchorProvider(EstTrustAnchorOptions options)
    {
        foreach (var certificate in options.TrustAnchors.Concat(options.AdditionalChainCertificates))
        {
            certificate.ValidateCertificateAuthority();
        }

        TrustAnchors = Array.AsReadOnly(options.TrustAnchors
            .Cast<X509Certificate2>()
            .Select(Clone)
            .ToArray());
        AdditionalChainCertificates = Array.AsReadOnly(options.AdditionalChainCertificates
            .Cast<X509Certificate2>()
            .Select(Clone)
            .ToArray());
    }

    public IReadOnlyCollection<X509Certificate2> TrustAnchors { get; }

    public IReadOnlyCollection<X509Certificate2> AdditionalChainCertificates { get; }

    private static X509Certificate2 Clone(X509Certificate2 certificate) =>
        X509CertificateLoader.LoadCertificate(certificate.RawData);
}
