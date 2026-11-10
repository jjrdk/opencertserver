namespace OpenCertServer.Ca;

using OpenCertServer.Ca.Utils.Ca;

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
    /// <summary>
    /// Gets the configured CRL distribution point URL templates. A template may contain the
    /// <see cref="ProfileToken"/> placeholder, which is replaced by the issuing profile name.
    /// </summary>
    public string[] CrlUrls { get; }

    /// <summary>
    /// The placeholder in a CRL URL template that is replaced with the issuing profile name.
    /// </summary>
    public const string ProfileToken = "{profile}";

    private bool _crlUrlsValidated;
    public string[] CaIssuersUrls { get; }

    /// <summary>
    /// Gets a value indicating whether strict OCSP HTTP binding is enforced, including content-type validation for POST requests.
    /// </summary>
    public bool StrictOcspHttpBinding { get; }

    /// <summary>
    /// Resolves the CRL distribution point URLs for the given profile by substituting
    /// <see cref="ProfileToken"/> with the URL-escaped profile name.
    /// </summary>
    /// <param name="profileName">The issuing profile name.</param>
    /// <returns>The profile-specific CRL URLs.</returns>
    public string[] GetCrlUrls(string profileName)
    {
        ArgumentNullException.ThrowIfNull(profileName);
        var escaped = Uri.EscapeDataString(profileName);
        return CrlUrls
            .Select(u => u.Replace(ProfileToken, escaped, StringComparison.OrdinalIgnoreCase))
            .ToArray();
    }

    /// <summary>
    /// Ensures that CRL URLs are partitioned per profile. Every profile publishes a CRL scoped to the
    /// certificates it issued, so when more than one profile exists every configured CRL URL must contain
    /// <see cref="ProfileToken"/>; otherwise certificates from different profiles would point relying parties
    /// at the same distribution point while each profile's CRL only covers its own certificates.
    /// </summary>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <exception cref="InvalidOperationException">Thrown when the configuration is not profile-partitioned.</exception>
    public async Task ValidateCrlUrlsAsync(CancellationToken cancellationToken = default)
    {
        if (_crlUrlsValidated || CrlUrls.Length == 0
         || CrlUrls.All(u => u.Contains(ProfileToken, StringComparison.OrdinalIgnoreCase)))
        {
            _crlUrlsValidated = true;
            return;
        }

        var count = 0;
        await foreach (var _ in Profiles.GetProfiles(cancellationToken).ConfigureAwait(false))
        {
            if (++count > 1)
            {
                throw new InvalidOperationException(
                    $"The CA has multiple profiles but CRL distribution point URLs are not partitioned per profile. Every CRL URL must contain the '{ProfileToken}' placeholder, e.g. 'http://host/ca/{ProfileToken}/crl'.");
            }
        }

        _crlUrlsValidated = true;
    }

    public void Dispose()
    {
        Profiles.Dispose();
        GC.SuppressFinalize(this);
    }
}
