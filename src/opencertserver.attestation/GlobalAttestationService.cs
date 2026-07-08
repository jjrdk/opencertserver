using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace OpenCertServer.Attestation;

/// <summary>
/// Orchestrates attestation provider selection based on cloud context and vendor preference
/// per spec section 2.2 and the cloud mapping table in section 6.1.
/// </summary>
public sealed class GlobalAttestationService
{
    /// <summary>
    /// Maps vendor names to their configuration section prefix (used by <see cref="GetEndpointForVendor"/>).
    /// </summary>
    private static readonly Dictionary<string, string> VendorToConfigSection = new(StringComparer.OrdinalIgnoreCase)
    {
        { "Intel", "Providers:IntelSgx" },
        { "AMD",   "Providers:AmdSevSnp" },
        { "Apple", "Providers:AppleSE" }
    };

    /// <summary>
    /// Default vendor per cloud context when no explicit <see cref="AttestationOptions.VendorPreference"/> is set.
    /// All combinations from spec table 6.1 are represented; any cloud+vendor pair is valid as long
    /// as the corresponding provider is registered.
    /// </summary>
    private static readonly Dictionary<string, string> DefaultVendorByCloud = new(StringComparer.OrdinalIgnoreCase)
    {
        { "Azure",  "Intel" },
        { "AWS",    "Intel" },
        { "Client", "Apple" },
        { "Local",  "Intel" }
    };

    private readonly AttestationOptions _options;
    private readonly IServiceProvider _serviceProvider;

    public GlobalAttestationService(IOptions<AttestationOptions> options, IServiceProvider serviceProvider)
    {
        _options = options.Value;
        _serviceProvider = serviceProvider;
    }

    /// <summary>
    /// Selects the <see cref="IAttestationProvider"/> appropriate for the current environment.
    /// Uses <see cref="AttestationOptions.VendorPreference"/> when set; otherwise falls back to
    /// the default vendor for the configured <see cref="AttestationOptions.CloudContext"/>.
    /// </summary>
    public IAttestationProvider GetProvider()
    {
        var vendor = ResolveVendor();
        return _serviceProvider.GetServices<IAttestationProvider>()
            .FirstOrDefault(p => string.Equals(p.VendorName, vendor, StringComparison.OrdinalIgnoreCase))
            ?? throw new NotSupportedException(
                $"No '{vendor}' attestation provider is registered. " +
                $"Ensure the provider is added via AddAttestationServices().");
    }

    /// <summary>
    /// Returns the primary endpoint URL for the given vendor based on the active cloud context.
    /// </summary>
    public string GetEndpointForVendor(string vendor)
    {
        if (!VendorToConfigSection.TryGetValue(vendor, out var section))
            throw new NotSupportedException($"Vendor '{vendor}' has no known configuration section.");

        var cloudContext = _options.CloudContext;

        // Select the cloud-specific endpoint override when available.
        // Endpoint priority: CloudContext-specific > generic PccsUrl/VpsUrl/VerifyUrl.
        return vendor switch
        {
            var v when string.Equals(v, "Intel", StringComparison.OrdinalIgnoreCase) =>
                cloudContext switch
                {
                    "AWS"   => "https://nitro-enclaves.us-east-1.amazonaws.com",
                    _       => _options.IntelSgx.PccsUrl
                },
            var v when string.Equals(v, "AMD", StringComparison.OrdinalIgnoreCase) =>
                _options.AmdSevSnp.VpsUrl,
            var v when string.Equals(v, "Apple", StringComparison.OrdinalIgnoreCase) =>
                _options.AppleSE.VerifyUrl,
            _ => throw new NotSupportedException($"No endpoint mapping for vendor '{vendor}'.")
        };
    }

    private string ResolveVendor()
    {
        if (!string.IsNullOrWhiteSpace(_options.VendorPreference))
            return _options.VendorPreference!;

        if (DefaultVendorByCloud.TryGetValue(_options.CloudContext, out var defaultVendor))
            return defaultVendor;

        throw new NotSupportedException(
            $"Cloud context '{_options.CloudContext}' has no default vendor mapping. " +
            $"Set 'VendorPreference' in configuration to specify the vendor explicitly.");
    }
}
