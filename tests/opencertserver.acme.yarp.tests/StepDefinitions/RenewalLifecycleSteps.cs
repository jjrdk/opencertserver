namespace OpenCertServer.Acme.Yarp.Tests.StepDefinitions;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Acme.AspNetClient.Certes;
using CertesSlim.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Acme.Abstractions.AcmeRoute;
using Reqnroll;
using Xunit;

[Binding]
public partial class RenewalLifecycleSteps
{
    private readonly AcmeRouteScope _scope = new();
    private readonly RecordingLifecycleHook _hook = new();
    private readonly List<IAcmeRouteConfiguration> _routes = [];
    private readonly Dictionary<string, string> _hosts = [];
    private readonly HashSet<string> _throwing = new(StringComparer.Ordinal);
    private X509Certificate2? _referenceCertificate;

    [Given(@"the ACME route ""(.+)"" for host ""(.+)""")]
    public void GivenTheAcmeRouteForHost(string routeId, string host)
    {
        _routes.Add(new RouteConfiguration(routeId, [host]));
        _hosts[routeId] = host;
    }

    [Given(@"the route ""(.+)"" already has an issued certificate")]
    public void GivenTheRouteAlreadyHasAnIssuedCertificate(string routeId)
    {
        var cert = CertFor(_hosts[routeId]);
        _scope.SetCertificate(routeId, cert);
        _referenceCertificate = cert;
    }

    [Given(@"renewing ""(.+)"" throws")]
    public void GivenRenewingThrows(string routeId)
    {
        _throwing.Add(routeId);
    }

    private AcmeRenewalService BuildService()
    {
        var provider = new RoutingCertificateProvider((routeId, cancellationToken) => Renew(routeId, cancellationToken));
        var source = new InMemoryAcmeRouteConfigurationSource([.. _routes]);

        return new AcmeRenewalService(
             provider,
             [_hook],
             new FakeHostApplicationLifetime(),
             NullLogger<AcmeRenewalService>.Instance,
             new TestAcmeOptions
             {
                 AccountPassword = "test",
                 Domains = [.. _hosts.Values],
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
              _scope);
    }

    [When(@"the renewal service runs its initial issuance")]
    public async Task WhenTheRenewalServiceRunsItsInitialIssuance()
    {
        var service = BuildService();
        await service.StartAsync(CancellationToken.None);
    }

    [When(@"the renewal service runs a single pass for all routes")]
    public async Task WhenTheRenewalServiceRunsASinglePassForAllRoutes()
    {
        var service = BuildService();
        await service.RunAllRoutesOnce("test", CancellationToken.None);
    }

    [When(@"the renewal service is stopped")]
    public async Task WhenTheRenewalServiceIsStopped()
    {
        var service = BuildService();
        await service.StartAsync(CancellationToken.None);
        await service.StopAsync(CancellationToken.None);
    }

    [Then(@"the certificate for ""(.+)"" is for host ""(.+)""")]
    public void ThenTheCertificateForIsForHost(string routeId, string host)
    {
        var cert = _scope.GetCertificate(routeId);
        Assert.NotNull(cert);
        Assert.Equal(host, cert!.Subject.Replace("CN=", string.Empty).Trim());
    }

    [Then(@"the certificate for ""(.+)"" is unchanged")]
    public void ThenTheCertificateForIsUnchanged(string routeId)
    {
        var cert = _scope.GetCertificate(routeId);
        Assert.NotNull(cert);
        Assert.Equal(_referenceCertificate!.Thumbprint, cert!.Thumbprint);
    }

    [Then(@"the certificate for ""(.+)"" is changed")]
    public void ThenTheCertificateForIsChanged(string routeId)
    {
        var cert = _scope.GetCertificate(routeId);
        Assert.NotNull(cert);
        Assert.NotEqual(_referenceCertificate!.Thumbprint, cert!.Thumbprint);
    }

    [Then(@"no route failed during issuance")]
    public void ThenNoRouteFailedDuringIssuance()
    {
        Assert.Equal(0, _hook.ExceptionCount);
    }

    [Then(@"the lifecycle hook observed at least one start")]
    public void ThenTheLifecycleHookObservedAtLeastOneStart()
    {
        Assert.True(_hook.StartCount > 0);
    }

    [Then(@"the lifecycle hook observed at least one stop")]
    public void ThenTheLifecycleHookObservedAtLeastOneStop()
    {
        Assert.True(_hook.StopCount > 0);
    }

    [Then(@"the lifecycle hook observed at least one exception")]
    public void ThenTheLifecycleHookObservedAtLeastOneException()
    {
        Assert.NotEqual(0, _hook.ExceptionCount);
    }

    private async Task<X509Certificate2?> Renew(string routeId, CancellationToken cancellationToken)
    {
        if (_throwing.Contains(routeId))
        {
            throw new InvalidOperationException("dns outage");
        }

        return CertFor(_hosts[routeId]);
    }

    private static X509Certificate2 CertFor(string host)
          => SelfSignedCertificate.MakeWithSubject(
          host, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
}
