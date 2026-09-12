namespace OpenCertServer.Acme.Yarp.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Acme.Abstractions.Acme;
using Acme.AspNetClient.Certificates;
using Acme.AspNetClient.Certes;
using CertesSlim.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using Xunit;

/// <summary>
/// Covers §4.4 "AcmeRenewalService renews every ACME route on its own schedule". The renewal engine
/// iterates the <see cref="IAcmeRouteConfigurationSource"/>; a failure on one route does not block
/// the others; and stopping the service halts further renewals.
/// </summary>
public sealed class RenewalLifecycleTests
{
     private static AcmeRenewalService BuildService(
        IAcmeRouteConfigurationSource source,
        AcmeRouteScope scope,
        RecordingLifecycleHook hook,
        Func<string, CancellationToken, Task<X509Certificate2?>> renew)
             {
          var provider = new RoutingCertificateProvider(renew);

        var service = new AcmeRenewalService(
           provider,
            [hook],
           new FakeHostApplicationLifetime(),
           NullLogger<AcmeRenewalService>.Instance,
       new TestAcmeOptions
              {
        AccountPassword = "test",
         Domains = ["alpha.example.com", "beta.example.com"],
         CertificateSigningRequest = new CsrInfo
           {
            CountryName = "US",
            Locality = "Test",
            Organization = "OpenCertServer",
            OrganizationUnit = "Tests",
            State = "CA"
             }
        },
           source,
            scope);

      return service;
             }

   private static X509Certificate2 CertFor(string host)
          => SelfSignedCertificate.MakeWithSubject(
            host, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));

          [Fact]
    public async Task InitialIssuranceOnServiceStart()
            {
        var source = new InMemoryAcmeRouteConfigurationSource(
               [
             new RouteConfiguration("route.alpha", ["alpha.example.com"]),
             new RouteConfiguration("route.beta", ["beta.example.com"])
                ]);

        var scope = new AcmeRouteScope();
        var hook = new RecordingLifecycleHook();

        var service = BuildService(source, scope, hook, (routeId, ct) =>
                   {
            var cert = routeId switch
                      {
                       "route.alpha" => CertFor("alpha.example.com"),
                       "route.beta" => CertFor("beta.example.com"),
                     _ => null
                      };

            return Task.FromResult(cert);
                   });

        await service.StartAsync(CancellationToken.None);

        var alphaCert = scope.GetCertificate("route.alpha");
        var betaCert = scope.GetCertificate("route.beta");

        Assert.Equal("alpha.example.com", alphaCert!.Subject.Replace("CN=", string.Empty).Trim());
        Assert.Equal("beta.example.com", betaCert!.Subject.Replace("CN=", string.Empty).Trim());

        // No route failed on the initial issuance.
        Assert.Equal(0, hook.ExceptionCount);
        Assert.True(hook.StartCount > 0);
            }

          [Fact]
    public async Task RenewalFailureOfOneRouteDoesNotBlockOthers()
            {
        var source = new InMemoryAcmeRouteConfigurationSource(
               [
             new RouteConfiguration("route.alpha", ["alpha.example.com"]),
             new RouteConfiguration("route.beta", ["beta.example.com"])
                ]);

        var scope = new AcmeRouteScope();
        var existingAlpha = CertFor("alpha.example.com");
        scope.SetCertificate("route.alpha", existingAlpha);

        var hook = new RecordingLifecycleHook();

        var service = BuildService(source, scope, hook, (routeId, ct) =>
                    {
            if (routeId == "route.alpha")
                    {
                throw new InvalidOperationException("dns outage");
                   }

                return Task.FromResult<X509Certificate2?>(CertFor("beta.example.com"));
                    });

        await service.RunAllRoutesOnce("test");

        Assert.Equal(existingAlpha.Thumbprint, scope.GetCertificate("route.alpha")!.Thumbprint);
        Assert.NotEqual(existingAlpha.Thumbprint, scope.GetCertificate("route.beta")!.Thumbprint);
        Assert.NotEqual(0, hook.ExceptionCount);
             }

          [Fact]
    public async Task StoppedServiceHaltsAllRenewals()
            {
        var source = new InMemoryAcmeRouteConfigurationSource(
               [
             new RouteConfiguration("route.alpha", ["alpha.example.com"])
                ]);

        var scope = new AcmeRouteScope();
        var hook = new RecordingLifecycleHook();

        var service = BuildService(source, scope, hook, async (routeId, ct) =>
                   {
            await Task.Delay(1, ct).ConfigureAwait(false);
                return CertFor("alpha.example.com");
                  });

        await service.StartAsync(CancellationToken.None);
        await service.StopAsync(CancellationToken.None);

        Assert.True(hook.StartCount > 0);
        Assert.True(hook.StopCount > 0);
            }
}
