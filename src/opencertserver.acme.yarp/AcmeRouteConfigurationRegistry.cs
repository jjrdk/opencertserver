namespace OpenCertServer.Acme.Yarp;

using System.Collections.Concurrent;
using OpenCertServer.Acme.Abstractions.Acme;

/// <summary>
/// A thread-safe, mutable <see cref="IAcmeRouteConfigurationSource"/>. The
/// <see cref="AddAcmeRoutesConfigFilter"/> populates it at YARP config-load time; the renewal
/// service and the Kestrel SNI selector read it.
/// </summary>
public sealed class AcmeRouteConfigurationRegistry : IAcmeRouteConfigurationSource
{
    private readonly ConcurrentDictionary<string, IAcmeRouteConfiguration> _byRouteId = new();

     public void AddConfiguration(IAcmeRouteConfiguration configuration)
          {
             _byRouteId[configuration.RouteId] = configuration;
          }

    public IEnumerable<IAcmeRouteConfiguration> GetRouteConfigurations()
        {
          return _byRouteId.Values;
         }
}
