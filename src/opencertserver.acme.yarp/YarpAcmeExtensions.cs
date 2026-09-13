namespace OpenCertServer.Acme.Yarp;

using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using global::Yarp.ReverseProxy.Configuration;

/// <summary>
/// Entry-point extension methods that wire the YARP integration into an ASP.NET Core application.
/// </summary>
public static class YarpAcmeExtensions
{
    /// <summary>
    /// Registers the ACME-per-route plumbing: the mutable <see cref="AcmeRouteConfigurationRegistry"/>
    /// (exposed as <c>IAcmeRouteConfigurationSource</c>), and starts the YARP proxy.
    /// Call after <c>AddAcmeClient(...)</c> so the renewal engine is present.
    /// </summary>
    public static IReverseProxyBuilder AddAcmeProxy(this IServiceCollection services)
    {
        services.AddSingleton<AcmeRouteConfigurationRegistry>();
        services.AddSingleton<OpenCertServer.Acme.Abstractions.Acme.IAcmeRouteConfigurationSource>(
            sp => sp.GetRequiredService<AcmeRouteConfigurationRegistry>());

        return services.AddReverseProxy();
    }

    /// <summary>
    /// Attaches the ACME route config filter to an existing YARP proxy builder so that every
    /// ACME-enabled route is registered for renewal. This is a config-filter registration on the
    /// proxy <em>builder</em> (not a request-pipeline <c>Use*</c>); the name follows the YARP
    /// <c>Add*</c>/<c>With*</c> convention accordingly.
    /// </summary>
    public static IReverseProxyBuilder WithAcmeRouteFilter(this IReverseProxyBuilder builder)
    {
        return builder.AddConfigFilter<AddAcmeRoutesConfigFilter>();
    }

    /// <summary>
    /// Loads the supplied YARP routes (each possibly carrying an ACME metadata bag) into the
    /// proxy and attaches the ACME config filter.
    /// </summary>
    public static IReverseProxyBuilder UseReverseProxyAcme(
       this IReverseProxyBuilder builder,
       IReadOnlyList<RouteConfig> routes)
    {
        return builder
               .WithAcmeRouteFilter()
               .LoadFromMemory(routes, []);
    }
}
