using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Ca;

/// <summary>
/// Defines the configuration for the Certificate Authority.
/// </summary>
public record CaConfiguration : IDisposable
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CaConfiguration"/> class.
    /// </summary>
    /// <param name="profiles">The profiles for the CA.</param>
    /// <param name="ocspUrls">The URLs for OCSP responders.</param>
    /// <param name="crlUrls">The URLs for CRL distribution points.</param>
    /// <param name="caIssuersUrls">The URLs for CA issuer information.</param>
    /// <param name="strictOcspHttpBinding">Whether to enforce strict OCSP HTTP binding, including content-type validation for POST requests.</param>
    public CaConfiguration(
        IStoreCaProfiles profiles,
        string[] ocspUrls,
        string[] crlUrls,
        string[] caIssuersUrls,
        bool strictOcspHttpBinding = false)
    {
        Profiles = profiles;
        OcspUrls = ocspUrls;
        CrlUrls = crlUrls;
        CaIssuersUrls = caIssuersUrls;
        StrictOcspHttpBinding = strictOcspHttpBinding;
    }

    public IStoreCaProfiles Profiles { get; }

    public string[] OcspUrls { get; }
    public string[] CrlUrls { get; }
    public string[] CaIssuersUrls { get; }

    /// <summary>
    /// Gets a value indicating whether strict OCSP HTTP binding is enforced, including content-type validation for POST requests.
    /// </summary>
    public bool StrictOcspHttpBinding { get; }

    public void Dispose()
    {
        Profiles.Dispose();
        GC.SuppressFinalize(this);
    }
}
