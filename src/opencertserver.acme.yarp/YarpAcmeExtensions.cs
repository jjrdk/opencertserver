using OpenCertServer.Acme.Abstractions.AcmeRoute;

namespace OpenCertServer.Acme.Yarp;

using System.Collections.Generic;
using Microsoft.Extensions.DependencyInjection;
using global::Yarp.ReverseProxy.Configuration;

/// <summary>
/// Entry-point extension methods that wire the YARP integration into an ASP.NET Core application.
/// </summary>
public static class YarpAcmeExtensions
{
    extension(IServiceCollection services)
    {
        /// <summary>
        /// Registers the ACME-per-route plumbing: the mutable <see cref="AcmeRouteConfigurationRegistry"/>
        /// (exposed as <c>IAcmeRouteConfigurationSource</c>), and starts the YARP proxy.
        /// Call after <c>AddAcmeClient(...)</c> so the renewal engine is present.
        /// </summary>
        public IReverseProxyBuilder AddAcmeProxy()
        {
            services.AddSingleton<AcmeRouteConfigurationRegistry>();
            services.AddSingleton<IAcmeRouteConfigurationSource>(sp =>
                sp.GetRequiredService<AcmeRouteConfigurationRegistry>());

            return services.AddReverseProxy();
        }
    }

    extension(IReverseProxyBuilder builder)
    {
        /// <summary>
        /// Attaches the ACME route config filter to an existing YARP proxy builder so that every
        /// ACME-enabled route is registered for renewal. This is a config-filter registration on the
        /// proxy <em>builder</em> (not a request-pipeline <c>Use*</c>); the name follows the YARP
        /// <c>Add*</c>/<c>With*</c> convention accordingly.
        /// </summary>
        public IReverseProxyBuilder WithAcmeRouteFilter()
        {
            return builder.AddConfigFilter<AddAcmeRoutesConfigFilter>();
        }

        /// <summary>
        /// Loads the supplied YARP routes (each possibly carrying an ACME metadata bag) into the
        /// proxy and attaches the ACME config filter.
        /// </summary>
        public IReverseProxyBuilder UseReverseProxyAcme(IReadOnlyList<RouteConfig> routes)
        {
            return builder
                .WithAcmeRouteFilter()
                .LoadFromMemory(routes, []);
        }
    }
}
