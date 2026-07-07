using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Attestation.Config;

namespace OpenCertServer.Attestation;

public class GlobalAttestationService
{
    private readonly IConfiguration _config;
    private readonly IServiceProvider _serviceProvider;

    public GlobalAttestationService(IConfiguration config, IServiceProvider serviceProvider)
    {
        _config = config;
        _serviceProvider = serviceProvider;
    }

    public IAttestationProvider GetProvider()
    {
        var cloudContext = _config["Global:CloudContext"] ?? "Local";
        var vendor = SelectVendor(cloudContext);
        
        // In a real system, we would resolve the specific provider implementation from DI
        // For Task 1, we demonstrate the selection logic.
        return _serviceProvider.GetServices<IAttestationProvider>()
            .FirstOrDefault(p => p.VendorName == vendor) 
            ?? throw new NotSupportedException($"No provider found for vendor {vendor} in context {cloudContext}");
    }

    private string SelectVendor(string cloudContext)
    {
        return cloudContext switch
        {
            "Azure" => "Intel", // Defaulting to Intel for Azure in this demo as per spec mapping logic simplification
            "AWS" => "AMD",
            _ => throw new NotSupportedException($"Cloud context {cloudContext} is not mapped to a vendor.")
        };
    }

    public string GetEndpointForVendor(string vendor)
    {
        return _config[$"Providers:{vendor}:PccsUrl"] 
               ?? _config[$"Providers:{vendor}:VpsUrl"] 
               ?? _config[$"Providers:{vendor}:VerifyUrl"] 
               ?? throw new InvalidOperationException($"No endpoint configured for vendor {vendor}");
    }
}
