namespace OpenCertServer.Acme.Yarp.Tests;

using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Acme.Abstractions.Acme;
using Xunit;
using global::Yarp.ReverseProxy.Configuration;

/// <summary>
/// Covers §4.1 "Register an ACME certificate per YARP route". Each ACME-enabled route yields a
/// distinct <see cref="IAcmeRouteConfiguration"/>; a route without ACME metadata yields none; and
/// the route's <c>Match.Hosts</c> become the certificate SANs.
/// </summary>
public sealed class PerRouteRegistrationTests
{
     private static RouteConfig Route(
        string routeId,
        IEnumerable<string> hosts,
        RouteAcmeOptions? acme = null)
         {
        var route = new RouteConfig
              {
             RouteId = routeId,
             Match = new RouteMatch
              {
             Hosts = hosts is null ? null : [.. hosts]
             }
             };

        if (acme is not null)
              {
            return RouteAcmeMetadataExtensions.WithAcmeRoute(route, acme);
              }

        return route;
          }

        private static AcmeRouteConfigurationRegistry RunFilter(params RouteConfig[] routes)
            {
            var registry = new AcmeRouteConfigurationRegistry();
            var filter = new AddAcmeRoutesConfigFilter(registry, Microsoft.Extensions.Logging.Abstractions.NullLogger<AddAcmeRoutesConfigFilter>.Instance);

            var cts = CancellationToken.None;
            foreach (var route in routes)
                {
                 _ = filter.ConfigureRouteAsync(route, null, cts).AsTask().GetAwaiter().GetResult();
                  }

            return registry;
             }

        [Fact]
    public void EachAcmeRouteRegistersADistinctDescriptor()
         {
        var alpha = Route("route.alpha", ["alpha.example.com"], new RouteAcmeOptions());
        var beta = Route("route.beta", ["beta.example.com"], new RouteAcmeOptions());

        var registry = RunFilter(alpha, beta);

        var descriptors = registry.GetRouteConfigurations().ToArray();

        Assert.Equal(2, descriptors.Length);
        Assert.Equal("alpha.example.com", string.Join(",", descriptors.First(d => d.RouteId == "route.alpha").Hosts));
        Assert.Equal("beta.example.com", string.Join(",", descriptors.First(d => d.RouteId == "route.beta").Hosts));
         }

         [Fact]
    public void ARouteWithoutAcmeMetadataDoesNotRegister()
           {
        var alpha = Route("route.alpha", ["alpha.example.com"], new RouteAcmeOptions());
        var beta = Route("route.beta", ["beta.example.com"]);

        var registry = RunFilter(alpha, beta);

        var descriptors = registry.GetRouteConfigurations().ToArray();

        Assert.Single(descriptors);
        Assert.Equal("route.alpha", descriptors[0].RouteId);
          }

        [Fact]
    public void RouteHostsMapToCertificateSans()
         {
        var multi = Route(
             "route.multi",
            new[] { "multi1.example.com", "multi2.example.com" },
             new RouteAcmeOptions());

        var registry = RunFilter(multi);

        var descriptor = registry.GetRouteConfigurations().Single(d => d.RouteId == "route.multi");

        Assert.Equal(2, descriptor.Hosts.Count);
        Assert.Contains("multi1.example.com", descriptor.Hosts);
        Assert.Contains("multi2.example.com", descriptor.Hosts);
            }
}
