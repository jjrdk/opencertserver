namespace OpenCertServer.Acme.Yarp;

using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using OpenCertServer.Acme.Abstractions.Acme;
using global::Yarp.ReverseProxy.Configuration;

/// <summary>
/// A YARP <see cref="IProxyConfigFilter"/> that discovers ACME-enabled routes and registers a
/// <see cref="IAcmeRouteConfiguration"/> for each one into a shared
/// <see cref="AcmeRouteConfigurationRegistry"/>. This is the "startup-time config filter" the
/// YARP integration plan calls for: it runs at config-load time, before the ACME renewal service
/// performs its first renewal tick.
/// </summary>
public sealed class AddAcmeRoutesConfigFilter : IProxyConfigFilter
{
    private readonly AcmeRouteConfigurationRegistry _registry;
    private readonly ILogger _logger;

    public AddAcmeRoutesConfigFilter(AcmeRouteConfigurationRegistry registry, ILogger<AddAcmeRoutesConfigFilter> logger)
         {
         _registry = registry;
         _logger = logger;
         }

    public ValueTask<global::Yarp.ReverseProxy.Configuration.ClusterConfig> ConfigureClusterAsync(
        global::Yarp.ReverseProxy.Configuration.ClusterConfig cluster,
        CancellationToken cancellation)
            {
             return ValueTask.FromResult(cluster);
             }

    public ValueTask<global::Yarp.ReverseProxy.Configuration.RouteConfig> ConfigureRouteAsync(
        global::Yarp.ReverseProxy.Configuration.RouteConfig route,
        global::Yarp.ReverseProxy.Configuration.ClusterConfig? cluster,
        CancellationToken cancellation)
          {
           var hosts = route.Match?.Hosts;
           if (hosts is null || hosts.Count == 0)
              {
               return ValueTask.FromResult(route);
               }

            var options = RouteAcmeMetadataExtensions.TryReadOptions(route);
                   if (options is null || !options.Enabled)
                        {
                        return ValueTask.FromResult(route);
                          }

               var descriptor = new RouteConfiguration(
                     route.RouteId,
                     options.Hosts.Count > 0 ? options.Hosts : hosts,
                     options.CommonName,
                     null);

              _registry.AddConfiguration(descriptor);
               _logger.LogInformation("Registered ACME route '{RouteId}' for hosts [{Hosts}]",
                    descriptor.RouteId, string.Join(", ", descriptor.Hosts));

            return ValueTask.FromResult(route);
              }
}
