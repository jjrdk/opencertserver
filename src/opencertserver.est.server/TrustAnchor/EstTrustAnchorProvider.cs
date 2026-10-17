using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Est.Server.TrustAnchor;

internal sealed class EstTrustAnchorProvider : IEstTrustAnchorProvider
{
    public EstTrustAnchorProvider(EstTrustAnchorOptions options)
    {
        ValidateAuthorities(options.TrustAnchors, "trust anchor");
        ValidateAuthorities(options.AdditionalChainCertificates, "additional chain certificate");
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

    private static void ValidateAuthorities(X509Certificate2Collection certificates, string description)
    {
        foreach (var certificate in certificates)
        {
            var constraints = certificate.Extensions.OfType<X509BasicConstraintsExtension>()
                .FirstOrDefault();
            if (constraints?.CertificateAuthority != true)
            {
                throw new ArgumentException(
                    $"The configured {description} '{certificate.Subject}' must have Basic Constraints CA:TRUE.");
            }

            var keyUsage = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (keyUsage is not null && !keyUsage.KeyUsages.HasFlag(X509KeyUsageFlags.KeyCertSign))
            {
                throw new ArgumentException(
                    $"The configured {description} '{certificate.Subject}' must permit certificate signing.");
            }
        }
    }
}