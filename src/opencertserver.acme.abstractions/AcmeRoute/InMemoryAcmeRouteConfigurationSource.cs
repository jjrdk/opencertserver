namespace OpenCertServer.Acme.Abstractions.Acme;

 using System.Collections.Generic;
 using System.Collections.Immutable;

 /// <summary>
 /// A simple in-memory <see cref="IAcmeRouteConfigurationSource"/>. Used by tests and by the
 /// YARP integration filter to publish parsed route descriptors. The underlying collection is
 /// immutable, so <see cref="GetRouteConfigurations"/> is safe to enumerate from concurrent
 /// renewal loops without an external lock.
 /// </summary>
 public sealed class InMemoryAcmeRouteConfigurationSource : IAcmeRouteConfigurationSource
 {
     private readonly ImmutableArray<IAcmeRouteConfiguration> _routeConfigurations;

     public InMemoryAcmeRouteConfigurationSource(IEnumerable<IAcmeRouteConfiguration> routeConfigurations)
       {
          _routeConfigurations = [.. routeConfigurations];
       }

     public IEnumerable<IAcmeRouteConfiguration> GetRouteConfigurations()
       {
          return _routeConfigurations;
       }
 }
