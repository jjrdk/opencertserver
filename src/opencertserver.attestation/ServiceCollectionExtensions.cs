using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenCertServer.Attestation.Native;

namespace OpenCertServer.Attestation;

public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers all attestation services. Call after <c>services.AddOptions()</c>.
    /// Options are bound from the "Global" and "Providers" configuration sections.
    /// </summary>
    public static IServiceCollection AddAttestationServices(this IServiceCollection services, IConfiguration configuration)
    {
        // Bind the top-level cloud context
        services.Configure<AttestationOptions>(configuration.GetSection("Global"));

        // Overlay the per-vendor provider options
        services.Configure<AttestationOptions>(opts =>
        {
            configuration.GetSection("Providers:IntelSgx").Bind(opts.IntelSgx);
            configuration.GetSection("Providers:AmdSevSnp").Bind(opts.AmdSevSnp);
            configuration.GetSection("Providers:AppleSE").Bind(opts.AppleSE);
        });

        // Certificate cache (shared across providers)
        services.TryAddSingleton<ICertificateCache, InMemoryCertificateCache>();

        // Native interop implementations
        services.TryAddSingleton<ISgxNativeInterop, SgxNativeInterop>();
        services.TryAddSingleton<IAmdSnpNativeInterop, AmdSnpNativeInterop>();
        services.TryAddSingleton<IAppleAttestNativeInterop, AppleAttestNativeInterop>();

        // Attestation providers
        services.AddTransient<IAttestationProvider, SgxProvider>();
        services.AddTransient<IAttestationProvider, AmdSnpProvider>();
        services.AddTransient<IAttestationProvider, AppleSeProvider>();

        // Orchestration and trust
        services.TryAddSingleton<TrustStore>();
        services.TryAddTransient<GlobalAttestationService>();

        return services;
    }
}
