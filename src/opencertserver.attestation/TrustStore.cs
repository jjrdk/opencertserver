using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OpenCertServer.Attestation;

/// <summary>
/// Validates device certificate trust chains against hard-pinned vendor root CAs per spec section 4.3.
/// Uses <see cref="X509ChainTrustMode.CustomRootTrust"/> to prevent the OS certificate store from
/// interfering with trust decisions.
/// </summary>
public sealed class TrustStore
{
    private readonly Dictionary<string, X509Certificate2> _pinnedRoots = new(StringComparer.OrdinalIgnoreCase);
    private readonly ILogger<TrustStore> _logger;

    private readonly X509RevocationMode _revocationMode;

    public TrustStore(IOptions<AttestationOptions> options, ILogger<TrustStore> logger)
    {
        _logger = logger;
        _revocationMode = options.Value.RevocationMode;
        LoadPinnedRoots(options.Value);
    }

    private void LoadPinnedRoots(AttestationOptions opts)
    {
        TryLoadRoot("Intel", opts.IntelSgx.RootCA);
        TryLoadRoot("AMD", opts.AmdSevSnp.RootCA);
        // Apple's App Attest Root CA is embedded; it is not configurable.
        TryLoadEmbeddedAppleRoot();
    }

    private void TryLoadRoot(string vendor, string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return;

        if (File.Exists(path))
        {
            try
            {
                _pinnedRoots[vendor] = X509CertificateLoader.LoadCertificateFromFile(path);
                _logger.LogInformation("Pinned {Vendor} root CA loaded from {Path}", vendor, path);
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load {Vendor} root CA from {Path}; trying embedded resource.", vendor, path);
            }
        }

        // Fall back to assembly-embedded root CA (distributed with the package).
        TryLoadEmbeddedRoot(vendor);
    }

    private void TryLoadEmbeddedRoot(string vendor)
    {
        var assembly = typeof(TrustStore).Assembly;
        var resourceName = $"OpenCertServer.Attestation.Resources.{vendor.ToLowerInvariant()}_root.cer";
        using var stream = assembly.GetManifestResourceStream(resourceName);
        if (stream is null)
        {
            _logger.LogWarning("No embedded root CA found for vendor {Vendor} (resource '{Resource}'). " +
                               "Certificate chain validation for this vendor will fail.", vendor, resourceName);
            return;
        }

var certBytes = new byte[stream.Length];
stream.ReadExactly(certBytes);
_pinnedRoots[vendor] = X509CertificateLoader.LoadCertificate(certBytes);
        _logger.LogInformation("Pinned {Vendor} root CA loaded from embedded resources.", vendor);
    }

    private void TryLoadEmbeddedAppleRoot()
    {
        // Apple App Attest Root CA is a well-known public certificate.
        // It is embedded as a resource in this assembly.
        TryLoadEmbeddedRoot("Apple");
    }

    /// <summary>
    /// Validates the certificate chain for <paramref name="deviceCert"/> against the pinned
    /// root for <paramref name="vendor"/>. Uses <see cref="X509ChainTrustMode.CustomRootTrust"/>
    /// so the OS root store is never consulted.
    /// </summary>
    public (bool IsValid, string Error) ValidateChain(X509Certificate2 deviceCert, string vendor)
    {
        if (!_pinnedRoots.TryGetValue(vendor, out var pinnedRoot))
        {
            _logger.LogWarning("No pinned root CA available for vendor '{Vendor}'.", vendor);
            return (false, "Unknown Vendor");
        }

        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = _revocationMode;
        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        chain.ChainPolicy.CustomTrustStore.Add(pinnedRoot);

        bool isValid = chain.Build(deviceCert);

        if (!isValid)
        {
            var errors = string.Join("; ", chain.ChainStatus.Select(s => s.StatusInformation.Trim()));
            _logger.LogWarning("Chain validation failed for vendor {Vendor}: {Errors}", vendor, errors);
            return (false, "Untrusted Vendor Root");
        }

        return (true, string.Empty);
    }

    /// <summary>
    /// Exposes the set of vendors for which a pinned root CA has been loaded.
    /// </summary>
    public IReadOnlyCollection<string> PinnedVendors => _pinnedRoots.Keys.ToList().AsReadOnly();

    /// <summary>
    /// Test helper: registers a certificate as the pinned root for <paramref name="vendor"/>.
    /// Do NOT call in production code.
    /// </summary>
    internal void RegisterTestRoot(string vendor, X509Certificate2 root) =>
        _pinnedRoots[vendor] = root;
}
