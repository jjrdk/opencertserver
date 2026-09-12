namespace OpenCertServer.Acme.Abstractions.Acme;

/// <summary>
/// A simple in-memory <see cref="IAcmeRouteConfigurationSource"/>. Used by tests and by the
/// YARP integration filter to publish parsed route descriptors.
/// </summary>
public sealed class InMemoryAcmeRouteConfigurationSource : IAcmeRouteConfigurationSource
{
    private readonly List<IAcmeRouteConfiguration> _routeConfigurations;

    public InMemoryAcmeRouteConfigurationSource(IEnumerable<IAcmeRouteConfiguration> routeConfigurations)
     {
        _routeConfigurations = [.. routeConfigurations];
     }

    public IEnumerable<IAcmeRouteConfiguration> GetRouteConfigurations()
     {
         return _routeConfigurations;
     }
}
