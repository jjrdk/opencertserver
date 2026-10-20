using OpenCertServer.Acme.Abstractions.AcmeRoute;

namespace OpenCertServer.Acme.Yarp;

using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using global::Yarp.ReverseProxy.Configuration;

/// <summary>
/// A YARP <see cref="IProxyConfigFilter"/> that discovers ACME-enabled routes and registers a
/// <see cref="IAcmeRouteConfiguration"/> for each one into a shared
/// <see cref="AcmeRouteConfigurationRegistry"/>. This is the "startup-time config filter" the
/// YARP integration plan calls for: it runs at config-load time, before the ACME renewal service
/// performs its first renewal tick.
/// </summary>
public sealed partial class AddAcmeRoutesConfigFilter : IProxyConfigFilter
{
    private readonly AcmeRouteConfigurationRegistry _registry;
    private readonly ILogger _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="AddAcmeRoutesConfigFilter"/> class.
    /// </summary>
    /// <param name="registry">The ACME route configuration registry.</param>
    /// <param name="logger">The logger instance.</param>
    public AddAcmeRoutesConfigFilter(AcmeRouteConfigurationRegistry registry, ILogger<AddAcmeRoutesConfigFilter> logger)
    {
        _registry = registry;
        _logger = logger;
    }

    /// <summary>
    /// Configures the cluster by returning it as-is, since this filter does not modify clusters.
    /// </summary>
    /// <param name="cluster">The cluster configuration.</param>
    /// <param name="cancellation">The cancellation token.</param>
    /// <returns>The unmodified cluster configuration.</returns>
    public ValueTask<ClusterConfig> ConfigureClusterAsync(
        ClusterConfig cluster,
        CancellationToken cancellation)
    {
        return ValueTask.FromResult(cluster);
    }

    /// <summary>
    /// Configures the route by checking if it has ACME options enabled. If so, it registers a new
    /// <see cref="IAcmeRouteConfiguration"/> for the route into the <see cref="AcmeRouteConfigurationRegistry"/>.
    /// </summary>
    /// <param name="route">The route configuration.</param>
    /// <param name="cluster">The cluster configuration.</param>
    /// <param name="cancellation">The cancellation token.</param>
    /// <returns>The unmodified route configuration.</returns>
    public ValueTask<RouteConfig> ConfigureRouteAsync(
        RouteConfig route,
        ClusterConfig? cluster,
        CancellationToken cancellation)
    {
        var hosts = route.Match.Hosts;
        if (hosts is null || hosts.Count == 0)
        {
            return ValueTask.FromResult(route);
        }

        var options = route.TryReadOptions();
        if (options is null || !options.Enabled)
        {
            return ValueTask.FromResult(route);
        }

        var descriptor = new RouteConfiguration(
            route.RouteId,
            options.Hosts.Count > 0 ? options.Hosts : hosts,
            options.CommonName);

        _registry.AddConfiguration(descriptor);
        LogRegisteredAcmeRouteRouteidForHostsHosts(descriptor.RouteId, string.Join(", ", descriptor.Hosts));

        return ValueTask.FromResult(route);
    }

    [LoggerMessage(LogLevel.Information, "Registered ACME route '{RouteId}' for hosts [{Hosts}]")]
    partial void LogRegisteredAcmeRouteRouteidForHostsHosts(string routeId, string hosts);
}
