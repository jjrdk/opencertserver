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
    public CaConfiguration(
        CaProfileSet profiles,
        string[] ocspUrls,
        string[] crlUrls,
        string[] caIssuersUrls)
    {
        Profiles = profiles;
        OcspUrls = ocspUrls;
        CrlUrls = crlUrls;
        CaIssuersUrls = caIssuersUrls;
    }

    public CaProfileSet Profiles { get; }

    public string[] OcspUrls { get; }
    public string[] CrlUrls { get; }
    public string[] CaIssuersUrls { get; }

    public void Dispose()
    {
        Profiles.Dispose();
        GC.SuppressFinalize(this);
    }
}
