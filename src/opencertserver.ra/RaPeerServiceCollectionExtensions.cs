using Microsoft.Extensions.DependencyInjection;

namespace OpenCertServer.Ra;

/// <summary>Dependency-injection extensions for the outbound RA peer.</summary>
public static class RaPeerServiceCollectionExtensions
{
    /// <summary>Registers a configured HTTPS-only peer client.</summary>
    public static IServiceCollection AddRaPeerClient(
        this IServiceCollection services,
        Microsoft.Extensions.Configuration.IConfiguration configuration)
    {
        return services.AddRaPeerClient(configuration, null);
    }

    /// <summary>
    /// Registers a configured HTTPS-only peer client and optionally configures its outbound TLS
    /// handler, for example to present an RA client certificate.
    /// </summary>
    public static IServiceCollection AddRaPeerClient(
        this IServiceCollection services,
        Microsoft.Extensions.Configuration.IConfiguration configuration,
        Action<HttpClientHandler>? configureHandler)
    {
        var options = RaPeerOptions.FromConfiguration(configuration);
        services.AddSingleton(options);
        services.AddHttpClient<RaPeerClient>()
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                var handler = new HttpClientHandler();
                configureHandler?.Invoke(handler);
                return handler;
            });
        return services;
    }
}