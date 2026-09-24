namespace OpenCertServer.Acme.Yarp.Tests.StepDefinitions;

using System;
using System.Threading;
using System.Security.Cryptography.X509Certificates;
using Acme.AspNetClient;
using Acme.AspNetClient.Certes;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Acme.Abstractions.AcmeRoute;
using OpenCertServer.Acme.Yarp.Tests;
using Reqnroll;
using Xunit;

[Binding]
public partial class BackwardCompatibilitySteps
{
    private AcmeRenewalService? _service;

    [Given(@"a renewal service with no ACME-tagged route")]
    public void GivenARenewalServiceWithNoAcmeTaggedRoute()
    {
        var source = new InMemoryAcmeRouteConfigurationSource(Array.Empty<IAcmeRouteConfiguration>());
        var scope = new AcmeRouteScope();
        var provider = new RoutingCertificateProvider(async (routeId, _) =>
            {
                Assert.Equal(AcmeRouteConstants.DefaultRouteId, routeId);
                return CertFor("default.example.com");
            });

        _service = new AcmeRenewalService(
            provider,
            Array.Empty<ICertificateRenewalLifecycleHook>(),
            NullLogger<AcmeRenewalService>.Instance,
            new TestAcmeOptions
            {
                AccountPassword = "test",
                Domains = ["anything.example.com"],
                CertificateSigningRequest = new CertesSlim.Extensions.CsrInfo()
            },
            source,
            scope);
    }

    [When(@"I start the single-route renewal service")]
    public async Task WhenIStartTheSingleRouteRenewalService()
    {
        await _service!.StartAsync(CancellationToken.None).ConfigureAwait(false);
        await _service.StartedAsync(CancellationToken.None).ConfigureAwait(false);
    }

    [Then(@"a certificate is loaded for the default route")]
    public void ThenACertificateIsLoadedForTheDefaultRoute()
    {
        Assert.NotNull(_service!.Certificate);
    }

    private static X509Certificate2 CertFor(string host)
         => SelfSignedCertificate.MakeWithSubject(
           host, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
}
