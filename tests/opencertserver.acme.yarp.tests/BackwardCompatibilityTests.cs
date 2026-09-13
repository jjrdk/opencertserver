namespace OpenCertServer.Acme.Yarp.Tests;

using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using Acme.Abstractions.Acme;
using Acme.AspNetClient;
using Acme.AspNetClient.Certes;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Covers §4.6 "Existing single-listener usage keeps working": when no YARP route is ACME-tagged the
/// renewal service and the Kestrel SNI selector fall back to the <c>__default__</c> route scope, and
/// that default leaf is served for any SNI host.
/// </summary>
public sealed class BackwardCompatibilityTests
{
    private static X509Certificate2 CertFor(string host)
           => SelfSignedCertificate.MakeWithSubject(
             host, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));

    [Fact]
    public async Task AcmeRenewalServiceLoadsTheLeafFromTheDefaultRouteScope()
    {
        var source = new InMemoryAcmeRouteConfigurationSource(Array.Empty<IAcmeRouteConfiguration>());
        var scope = new AcmeRouteScope();

        // With no ACME-tagged route, the source falls back to the __default__ route.
        var routes = scope.GetRoutes(source).ToList();
        var defaultRoute = routes.Single();
        Assert.Equal(AcmeRouteConstants.DefaultRouteId, defaultRoute.RouteId);

        // Drive a renewal of the default route and confirm the leaf is loaded from that scope.
        var provider = new RoutingCertificateProvider(async (routeId, ct) =>
             {
                 Assert.Equal(AcmeRouteConstants.DefaultRouteId, routeId);
                 return CertFor("default.example.com");
             });

        var service = new AcmeRenewalService(
           provider,
           Array.Empty<ICertificateRenewalLifecycleHook>(),
           new FakeHostApplicationLifetime(),
           NullLogger<AcmeRenewalService>.Instance,
           new TestAcmeOptions
           {
               AccountPassword = "test",
               Domains = ["anything.example.com"],
               CertificateSigningRequest = new CertesSlim.Extensions.CsrInfo()
           },
           source,
           scope);

        await service.StartAsync(TestContext.Current.CancellationToken);

        var leaf = service.Certificate;
        Assert.NotNull(leaf);
    }


    [Fact]
    public void KestrelServesTheDefaultLeafForAnySniHostWhenNoRouteIsTagged()
    {
        var scope = new AcmeRouteScope();
        var defaultCert = CertFor("default.example.com");
        scope.SetCertificate(AcmeRouteConstants.DefaultRouteId, defaultCert);

        var source = new InMemoryAcmeRouteConfigurationSource(Array.Empty<IAcmeRouteConfiguration>());
        var renewalService = new TestRenewalService { Certificate = defaultCert };

        var setup = new KestrelOptionsSetup(
            renewalService,
           scope,
            source,
            NullLogger<KestrelOptionsSetup>.Instance);

        setup.Configure(new Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions());

        var selected = setup.SelectCertificateFor("anything.example.com");

        Assert.Equal(defaultCert.Thumbprint, selected!.Thumbprint);
    }
}
