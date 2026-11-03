namespace OpenCertServer.Ca.Client;

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// Dependency-injection extensions that wire a backing-CA client into a host. Registering these makes
/// the host's <see cref="ICertificateAuthority"/> a remote one, so an ACME server or RA process issues
/// and revokes through a trusted HTTPS connection instead of an in-process CA.
/// </summary>
public static class CaClientServiceCollectionExtensions
{
    /// <summary>
    /// Registers a backing-CA client read from the <c>Ca</c> configuration section and exposes it as the
    /// host's <see cref="ICertificateAuthority"/>. This is the wiring selected by
    /// <c>AcmeServer:Issuer=remote</c>.
    /// </summary>
    public static IServiceCollection AddCaClient(this IServiceCollection services, IConfiguration configuration)
    {
        var options = CaClientOptions.FromConfiguration(configuration);
        return services.AddCaClient(options);
    }

    /// <summary>Registers a backing-CA client from explicit options.</summary>
    public static IServiceCollection AddCaClient(this IServiceCollection services, CaClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (options.BaseUrl.Scheme != Uri.UriSchemeHttps)
        {
            throw new InvalidOperationException("Backings CA connections must use HTTPS.");
        }

        var revokeIdentity = LoadRevokeIdentity(options);

        services.AddSingleton(options);
        services.AddHttpClient<CaClient>(client => client.BaseAddress = options.BaseUrl)
            .ConfigurePrimaryHttpMessageHandler(() =>
            {
                var handler = new HttpClientHandler();
                options.ConfigureHandler(handler);
                return handler;
            });

        services.AddSingleton<ICertificateAuthority>(sp =>
            new RemoteCertificateAuthority(sp.GetRequiredService<CaClient>(), revokeIdentity));

        return services;
    }

    private static X509Certificate2? LoadRevokeIdentity(CaClientOptions options)
    {
        if (string.IsNullOrWhiteSpace(options.ClientCertPath))
        {
            return null;
        }

        var client = X509CertificateLoader.LoadPkcs12(
            System.IO.File.ReadAllBytes(options.ClientCertPath),
            string.IsNullOrEmpty(options.ClientCertPassword) ? string.Empty : options.ClientCertPassword);
        return client.HasPrivateKey ? client : null;
    }
}
