namespace OpenCertServer.Acme.Yarp.Tests.StepDefinitions;

using System.Linq;
using System.Threading;
using Microsoft.Extensions.Logging.Abstractions;
using Reqnroll;
using global::Yarp.ReverseProxy.Configuration;
using Xunit;

[Binding]
public partial class PerRouteRegistrationSteps
{
    private readonly List<RouteConfig> _pendingRoutes = [];
    private AcmeRouteConfigurationRegistry? _registry;

    [Given(@"an ACME route ""(.+)"" for host ""(.+)""")]
    public void GivenAnAcmeRouteForHost(string routeId, string host)
    {
        _pendingRoutes.Add(Route(routeId, [host], new RouteAcmeOptions()));
    }

    [Given(@"a plain route ""(.+)"" for host ""(.+)""")]
    public void GivenAPlainRouteForHost(string routeId, string host)
    {
        _pendingRoutes.Add(Route(routeId, [host]));
    }

    [Given(@"an ACME route ""(.+)"" for hosts ""(.+)""")]
    public void GivenAnAcmeRouteForHosts(string routeId, string hosts)
    {
        var sanList = hosts
             .Split(",", StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
             .ToArray();
        _pendingRoutes.Add(Route(routeId, [.. sanList], new RouteAcmeOptions()));
    }

    [When(@"the ACME config filter processes the routes")]
    public void WhenTheAcmeConfigFilterProcessesTheRoutes()
    {
        var registry = new AcmeRouteConfigurationRegistry();
        var filter = new AddAcmeRoutesConfigFilter(
            registry,
            NullLogger<AddAcmeRoutesConfigFilter>.Instance);

        foreach (var route in _pendingRoutes)
        {
            _ = filter.ConfigureRouteAsync(route, null, CancellationToken.None)
                 .AsTask()
                 .GetAwaiter()
                 .GetResult();
        }

        _registry = registry;
    }

    [Then(@"route ""(.+)"" contains host ""(.+)""")]
    public void ThenTheRouteContainsHost(string routeId, string host)
    {
        var descriptor = _registry!.GetRouteConfigurations().First(d => d.RouteId == routeId);
        Assert.Contains(host, descriptor.Hosts);
    }

    [Then(@"route ""(.+)"" contains (\d+) hosts")]
    public void ThenTheRouteContainsHosts(string routeId, int expectedCount)
    {
        var descriptor = _registry!.GetRouteConfigurations().First(d => d.RouteId == routeId);
        Assert.Equal(expectedCount, descriptor.Hosts.Count);
    }

    [Then(@"exactly one ACME route is registered")]
    public void ThenExactlyOneAcmeRouteIsRegistered()
    {
        var descriptors = _registry!.GetRouteConfigurations().ToArray();
        Assert.Single(descriptors);
        Assert.Equal("route.alpha", descriptors[0].RouteId);
    }

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
}
