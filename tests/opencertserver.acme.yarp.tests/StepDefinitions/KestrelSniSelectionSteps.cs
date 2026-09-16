namespace OpenCertServer.Acme.Yarp.Tests.StepDefinitions;

using System;
using System.Security.Cryptography.X509Certificates;
using Acme.AspNetClient;
using Acme.AspNetClient.Certes;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Acme.Abstractions.AcmeRoute;
using OpenCertServer.Acme.Yarp.Tests;
using Reqnroll;
using Xunit;

[Binding]
public partial class KestrelSniSelectionSteps
{
    private readonly AcmeRouteScope _scope = new();
    private readonly List<IAcmeRouteConfiguration> _routes = [];
    private readonly Dictionary<string, X509Certificate2> _certificates = [];
    private X509Certificate2? _selected;

    [Given(@"route ""(.+)"" serves ""(.+)""")]
    public void GivenRouteServes(string routeId, string host)
    {
        var cert = CertFor(host);
        _scope.SetCertificate(routeId, cert);
        _certificates[routeId] = cert;
        _routes.Add(new RouteConfiguration(routeId, [host]));
    }

    [Given(@"the default route is served by a certificate")]
    public void GivenTheDefaultRouteIsServedByACertificate()
    {
        var cert = CertFor(AcmeRouteConstants.DefaultRouteId);
        _scope.SetCertificate(AcmeRouteConstants.DefaultRouteId, cert);
        _certificates[AcmeRouteConstants.DefaultRouteId] = cert;
    }

    [Then(@"I renew ""(.+)"" with a fresh certificate")]
    public void ThenIRenewWithAFreshCertificate(string routeId)
    {
        var fresh = CertFor($"{routeId}-renewed");
        _scope.SetCertificate(routeId, fresh);
        _certificates[routeId] = fresh;
    }

    [When(@"Kestrel selects a certificate for SNI host ""(.+)""")]
    public void WhenKestrelSelectsACertificateForSniHost(string host)
    {
        var source = new InMemoryAcmeRouteConfigurationSource([.. _routes]);
        var setup = new KestrelOptionsSetup(
            new TestRenewalService(),
            _scope,
            source,
            NullLogger<KestrelOptionsSetup>.Instance);

        setup.Configure(new KestrelServerOptions());
        _selected = setup.SelectCertificateFor(host);
    }

    [Then(@"the selected certificate is the certificate for ""(.+)""")]
    public void ThenTheSelectedCertificateIsTheCertificateFor(string routeId)
    {
        Assert.Equal(_certificates[routeId].Thumbprint, _selected!.Thumbprint);
    }

    [Then(@"the selected certificate is the default leaf")]
    public void ThenTheSelectedCertificateIsTheDefaultLeaf()
    {
        var expected = _certificates[AcmeRouteConstants.DefaultRouteId];
        Assert.Equal(expected.Thumbprint, _selected!.Thumbprint);
    }

    private static X509Certificate2 CertFor(string subject)
                       => SelfSignedCertificate.MakeWithSubject(
                        subject, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
}
