using OpenCertServer.Acme.Abstractions.AcmeRoute;

namespace OpenCertServer.Acme.Yarp;

using System.Collections.Concurrent;

/// <summary>
/// A thread-safe, mutable <see cref="IAcmeRouteConfigurationSource"/>. The
/// <see cref="AddAcmeRoutesConfigFilter"/> populates it at YARP config-load time; the renewal
/// service and the Kestrel SNI selector read it.
/// </summary>
public sealed class AcmeRouteConfigurationRegistry : IAcmeRouteConfigurationSource
{
    private readonly ConcurrentDictionary<string, IAcmeRouteConfiguration> _byRouteId = new();

    /// <summary>
    /// Registers or updates an ACME route descriptor.
    /// </summary>
    /// <remarks>
    /// <b>Known limitation (v1):</b> there is no removal API. If a YARP route is removed via
    /// hot-config-reload, its descriptor remains registered here until the process is restarted,
    /// and the renewal service and SNI selector keep servicing it. Runtime route removal is
    /// tracked as a future enhancement; it will be wired to the YARP
    /// <c>IProxyConfigProvider</c> change token when hot-reload is implemented.
    /// </remarks>
    public void AddConfiguration(IAcmeRouteConfiguration configuration)
    {
        _byRouteId[configuration.RouteId] = configuration;
    }

    public IEnumerable<IAcmeRouteConfiguration> GetRouteConfigurations()
    {
        return _byRouteId.Values;
    }
}
