namespace OpenCertServer.Acme.Yarp.Tests;

using System;
using Acme.Abstractions.Acme;
using Acme.AspNetClient;
using Acme.AspNetClient.Certes;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Covers §4.3 "Select the correct certificate per host via SNI" using the
/// <see cref="KestrelOptionsSetup"/> SNI selection logic. A real Kestrel <c>ServerCertificateSelector</c>
/// calls back into this same selection path, so verifying
/// <c>SelectCertificateFor</c> covers the live behaviour described in the plan.
/// </summary>
public sealed class KestrelSniSelectionTests
{
    private static KestrelOptionsSetup BuildSetup(
       IAcmeRouteConfigurationSource source,
       AcmeRouteScope scope,
       IAcmeRenewalService renewalService)
    {
        var setup = new KestrelOptionsSetup(
            renewalService,
         scope,
          source,
           NullLogger<KestrelOptionsSetup>.Instance);

        setup.Configure(new Microsoft.AspNetCore.Server.Kestrel.Core.KestrelServerOptions());

        return setup;
    }

    [Fact]
    public void SniSelectsTheCertificateWhoseHostIsInTheRoute()
    {
        var scope = new AcmeRouteScope();

        var alphaCert = SelfSignedCertificate.MakeWithSubject("alpha.example.com", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
        var betaCert = SelfSignedCertificate.MakeWithSubject("beta.example.com", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));

        scope.SetCertificate("route.alpha", alphaCert);
        scope.SetCertificate("route.beta", betaCert);

        var source = new InMemoryAcmeRouteConfigurationSource(
             [
             new RouteConfiguration("route.alpha", ["alpha.example.com"]),
             new RouteConfiguration("route.beta", ["beta.example.com"])
             ]);

        var setup = BuildSetup(source, scope, new TestRenewalService());

        var selected = setup.SelectCertificateFor("alpha.example.com");

        Assert.Equal(alphaCert.Thumbprint, selected!.Thumbprint);
    }

    [Fact]
    public void SniRejectsAnUnknownHostWithADefaultFallback()
    {
        var scope = new AcmeRouteScope();

        var defaultCert = SelfSignedCertificate.MakeWithSubject("__default__", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
        scope.SetCertificate(Acme.Abstractions.Acme.AcmeRouteConstants.DefaultRouteId, defaultCert);

        var source = new InMemoryAcmeRouteConfigurationSource(
             [
             new RouteConfiguration("route.alpha", ["alpha.example.com"])
             ]);

        var setup = BuildSetup(source, scope, new TestRenewalService());

        var selected = setup.SelectCertificateFor("unknown.example.com");

        Assert.Equal(defaultCert.Thumbprint, selected!.Thumbprint);
    }

    [Fact]
    public void ARenewedCertificateIsPickedUpOnTheNextHandshake()
    {
        var scope = new AcmeRouteScope();

        var v1 = SelfSignedCertificate.MakeWithSubject("alpha.example.com", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(89));
        var v2 = SelfSignedCertificate.MakeWithSubject("alpha.example.com", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(111));

        scope.SetCertificate("route.alpha", v1);

        var source = new InMemoryAcmeRouteConfigurationSource(
             [
             new RouteConfiguration("route.alpha", ["alpha.example.com"])
             ]);

        var setup = BuildSetup(source, scope, new TestRenewalService());

        var before = setup.SelectCertificateFor("alpha.example.com");
        Assert.Equal(v1.Thumbprint, before!.Thumbprint);

        scope.SetCertificate("route.alpha", v2);

        var after = setup.SelectCertificateFor("alpha.example.com");
        Assert.Equal(v2.Thumbprint, after!.Thumbprint);
    }
}
