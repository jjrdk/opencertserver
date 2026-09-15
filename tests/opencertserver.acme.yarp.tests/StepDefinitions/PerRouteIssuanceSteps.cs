namespace OpenCertServer.Acme.Yarp.Tests.StepDefinitions;

using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Cryptography.X509Certificates;
using Acme.AspNetClient;
using Acme.AspNetClient.Certes;
using Acme.AspNetClient.Certificates;
using Acme.AspNetClient.Persistence;
using CertesSlim.Extensions;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging.Abstractions;
using NSubstitute;
using OpenCertServer.Acme.Abstractions.AcmeRoute;
using Reqnroll;
using Xunit;

[Binding]
public class PerRouteIssuanceSteps
{
    private readonly AcmeRouteScope _scope = new();
    private readonly List<IAcmeRouteConfiguration> _routes = [];
    private InMemoryAcmeClient? _client;

    [Given(@"the YARP route ""(.+)"" for host ""(.+)""")]
    public void GivenTheYarpRouteForHost(string routeId, string host)
    {
        _routes.Add(new RouteConfiguration(routeId, [host]));
    }

    [When(@"the renewal service runs against a recording ACME client")]
    public async Task WhenTheRenewalServiceRunsAgainstARecordingAcmeClient()
    {
        _client = new InMemoryAcmeClient();
        var persistence = Substitute.For<IPersistenceService>();
        var validator = Substitute.For<IValidateCertificates>();
        validator.IsCertificateValid(Arg.Any<X509Certificate2?>()).Returns(false);
        var clientFactory = new TestAcmeClientFactory(_client);
        var source = new InMemoryAcmeRouteConfigurationSource([.. _routes]);

        var provider = new CertificateProvider(
             validator,
             persistence,
             clientFactory,
             NullLogger<CertificateProvider>.Instance);

        var service = new AcmeRenewalService(
            provider,
            Array.Empty<ICertificateRenewalLifecycleHook>(),
            new FakeHostApplicationLifetime(),
            NullLogger<AcmeRenewalService>.Instance,
            new TestAcmeOptions
            {
                AccountPassword = "test",
                Domains = [.. _routes.SelectMany(r => r.Hosts)],
                CertificateSigningRequest = new CsrInfo()
            },
            source,
             _scope);

        await service.RunAllRoutesOnce("test", CancellationToken.None);

        var setup = new KestrelOptionsSetup(
            new TestRenewalService(),
             _scope,
             source,
             NullLogger<KestrelOptionsSetup>.Instance);

        setup.Configure(new KestrelServerOptions());
        _setup = setup;
    }

    [Then(@"the order for route ""(.+)"" requested host ""(.+)""")]
    public void ThenTheOrderForRouteRequestedHost(string routeId, string host)
    {
        Assert.Contains(_client!.Orders, order => order.Contains(host));
    }

    [Then(@"two distinct ACME orders were placed")]
    public void ThenTwoDistinctAcmeOrdersWerePlaced()
    {
        Assert.Equal(2, _client!.Orders.Count);
        Assert.Equal(1, _client!.Orders.Count(o => o.Contains("alpha.example.com")));
        Assert.Equal(1, _client!.Orders.Count(o => o.Contains("beta.example.com")));
    }

    [Then(@"Kestrel serves the route ""(.+)"" certificate to host ""(.+)""")]
    public void ThenKestrelServesTheRouteCertificateToHost(string routeId, string host)
    {
        var selected = _setup!.SelectCertificateFor(host);
        var expected = _scope.GetCertificate(routeId);
        Assert.NotNull(expected);
        Assert.Equal(expected!.Thumbprint, selected!.Thumbprint);
    }

    [Then(@"the two routes serve different certificates")]
    public void ThenTheTwoRoutesServeDifferentCertificates()
    {
        var alpha = _setup!.SelectCertificateFor("alpha.example.com");
        var beta = _setup.SelectCertificateFor("beta.example.com");
        Assert.NotNull(alpha);
        Assert.NotNull(beta);
        Assert.NotEqual(alpha!.Thumbprint, beta!.Thumbprint);
    }

    private KestrelOptionsSetup? _setup;
}
