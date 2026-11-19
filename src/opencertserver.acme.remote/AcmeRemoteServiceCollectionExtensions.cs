namespace OpenCertServer.Acme.Remote;

using Acme.Abstractions.IssuanceServices;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenCertServer.Ca.Client;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// Dependency-injection extensions that turn an ACME host into a remote ACME server: they register a
/// backing-CA <see cref="CaClient"/> (and, for ACME revocation, the <c>ICertificateAuthority</c> it
/// exposes) and a <see cref="RemoteIssuer"/> so ACME orders are signed by the backing CA over a trusted
/// HTTPS connection. This is the wiring selected by <c>AcmeServer:Issuer=remote</c>.
/// </summary>
public static class AcmeRemoteServiceCollectionExtensions
{
    /// <summary>
    /// Registers a remote ACME issuer read from the <c>Ca</c> configuration section. The ACME server
    /// issues through the backing CA and hosts no CA core.
    /// </summary>
    public static IServiceCollection AddAcmeRemoteCa(this IServiceCollection services, IConfiguration configuration)
    {
        var options = CaClientOptions.FromConfiguration(configuration);
        return services.AddAcmeRemoteCa(options);
    }

    /// <summary>Registers a remote ACME issuer from explicit backing-CA client options.</summary>
    public static IServiceCollection AddAcmeRemoteCa(this IServiceCollection services, CaClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        services.AddCaClient(options);
        services.TryAddSingleton<IStoreCertificates, InMemoryCertificateStore>();
        services.AddSingleton<IIssueCertificates, RemoteIssuer>();
        return services;
    }
}
