using OpenCertServer.Acme.Abstractions.AcmeRoute;

namespace OpenCertServer.Acme.AspNetClient.Certes;

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using static Certificates.CertificateRenewalStatus;

public sealed partial class AcmeRenewalService : IAcmeRenewalService
{
    private readonly IProvideCertificates _certificateProvider;
    private readonly IEnumerable<ICertificateRenewalLifecycleHook> _lifecycleHooks;
    private readonly ILogger<IAcmeRenewalService> _logger;
    private readonly IHostApplicationLifetime _lifetime;
    private readonly SemaphoreSlim _semaphoreSlim;
    private readonly AcmeOptions _options;
    private readonly IAcmeRouteConfigurationSource _routeConfigurationSource;
    private readonly AcmeRouteScope _routeScope;

    private Task? _renewalLoop;
    private CancellationTokenSource? _renewalCts;

    public AcmeRenewalService(
        IProvideCertificates certificateProvider,
        IEnumerable<ICertificateRenewalLifecycleHook> lifecycleHooks,
        IHostApplicationLifetime lifetime,
        ILogger<AcmeRenewalService> logger,
        AcmeOptions options,
        IAcmeRouteConfigurationSource routeConfigurationSource,
        AcmeRouteScope routeScope)
    {
        _certificateProvider = certificateProvider;
        _lifecycleHooks = lifecycleHooks;
        _lifetime = lifetime;
        _logger = logger;
        _options = options;
        _routeScope = routeScope;
        _routeConfigurationSource = routeConfigurationSource;
        _semaphoreSlim = new SemaphoreSlim(1);
    }

    public X509Certificate2? Certificate
    {
        get { return _routeScope.GetCertificate(AcmeRouteConstants.DefaultRouteId); }
    }

    public Uri LetsEncryptUri
    {
        get { return _options.AcmeServerUri; }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (_options.TimeAfterIssueDateBeforeRenewal == null && _options.TimeUntilExpiryBeforeRenewal == null)
        {
            throw new InvalidOperationException(
                "Neither TimeAfterIssueDateBeforeRenewal nor TimeUntilExpiryBeforeRenewal have been set, which means that the LetsEncrypt certificate will never renew.");
        }

        LogAcmerenewalserviceStartasync();

        foreach (var lifecycleHook in _lifecycleHooks)
        {
            await lifecycleHook.OnStart().ConfigureAwait(false);
        }

        await ValidateDomainsConfiguredAsync().ConfigureAwait(false);

        // Initial issuance for every registered route, isolated so one failure does not block the others.
        await RunAllRoutesOnce(_options.AccountPassword, cancellationToken).ConfigureAwait(false);

        _renewalCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _renewalLoop = RunRenewalLoopAsync(_renewalCts.Token);

        _lifetime.ApplicationStopping.Register(OnApplicationStopping);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        LogTheLetsencryptMiddlewareSBackgroundRenewalThreadIsShuttingDown();

        // Halt any future ticks and drain the in-flight renewal pass so certificate files are not
        // left partially written and in-flight ACME orders are not abandoned.
        _renewalCts?.Cancel();
        if (_renewalLoop is not null)
        {
            try
            {
                await _renewalLoop.ConfigureAwait(ConfigureAwaitOptions.SuppressThrowing);
            }
            catch (OperationCanceledException)
            {
            }
        }

        foreach (var lifecycleHook in _lifecycleHooks)
        {
            await lifecycleHook.OnStop().ConfigureAwait(false);
        }
    }

    ///<summary>
    /// Back-compat single-route renewal for the default route. Delegates to the per-route
    /// renewal pass.
    /// </summary>
    public Task RunOnce(string password)
    {
        return RunAllRoutesOnce(password);
    }

    public async Task RunAllRoutesOnce(string password, CancellationToken cancellationToken = default)
    {
        if (_semaphoreSlim.CurrentCount == 0)
        {
            return;
        }

        await _semaphoreSlim.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            var routes = _routeScope.GetRoutes(_routeConfigurationSource);

            foreach (var route in routes)
            {
                try
                {
                    var current = _routeScope.GetCertificate(route.RouteId);
                    IReadOnlyList<string> hosts = route.Hosts.Count > 0 ? route.Hosts : _options.Domains;
                    var outcome = await _certificateProvider.RenewCertificateIfNeeded(
                        password, route.RouteId, hosts, current, cancellationToken).ConfigureAwait(false);
                    ApplyOutcome(route.RouteId, outcome);
                    await WarmChain(outcome, cancellationToken).ConfigureAwait(false);
                    await FireRenewalSucceededHooks(outcome).ConfigureAwait(false);
                    LogRenewedRoute(route.RouteId, outcome.Status);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    // Failure isolation: a failed route must not block the others. The
                    // previous leaf for this route remains in use (unless RenewFailOver is set).
                    await FireExceptionHooks(ex).ConfigureAwait(false);
                    LogRenewalFailedForRoute(route.RouteId, ex);
                }
            }
        }
        finally
        {
            _semaphoreSlim.Release();
        }
    }

    private async Task ValidateDomainsConfiguredAsync()
    {
        var routes = _routeScope.GetRoutes(_routeConfigurationSource);
        var hasRouteHosts = routes.Any(r => r.Hosts.Count > 0);
        if (hasRouteHosts || _options.Domains.Distinct().Any())
        {
            return;
        }

        throw new InvalidOperationException(
            "No domains are configured. Either set AcmeOptions.Domains or register at least one "
          + "ACME route with non-empty hosts via the YARP integration.");
    }

    private void ApplyOutcome(string routeId, CertificateRenewalResult result)
    {
        _routeScope.SetCertificate(routeId, result.Certificate);
    }

    private async Task WarmChain(CertificateRenewalResult outcome, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (outcome.Status != Unchanged && outcome.Certificate != null)
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            if (chain.Build(outcome.Certificate))
            {
                LogSuccessfullyBuiltCertificateChain();
            }
            else
            {
                LogWasNotAbleToBuildCertificateChainThisCanCauseAnOutageOfYourApp();
            }
        }
    }

    private async Task FireRenewalSucceededHooks(CertificateRenewalResult result)
    {
        if (result.Status == Renewed)
        {
            foreach (var lifecycleHook in _lifecycleHooks)
            {
                await lifecycleHook.OnRenewalSucceeded().ConfigureAwait(false);
            }
        }
    }

    private async Task FireExceptionHooks(Exception ex)
    {
        foreach (var lifecycleHook in _lifecycleHooks)
        {
            await lifecycleHook.OnException(ex).ConfigureAwait(false);
        }
    }

    private async Task RunRenewalLoopAsync(CancellationToken cancellationToken)
    {
        try
        {
            await Task.Delay(_options.RenewalServiceStartupDelay, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return;
        }

        using var timer = new PeriodicTimer(TimeSpan.FromHours(1));
        while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
        {
            try
            {
                LogAcmerenewalserviceTimerCallbackStarting();
                await RunAllRoutesOnce(_options.AccountPassword, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                // Shutdown: the loop is being stopped, so don't treat the cancellation as a
                // renewal failure.
                break;
            }
            catch (Exception e) when (_options.RenewalFailMode != RenewalFailMode.Unhandled)
            {
                LogExceptionOccurredRenewingCertificatesMessage(e, e.Message);
            }
        }
    }

    private void OnApplicationStopping()
    {
        // Ensure the renewal loop is stopped when the host signals shutdown, so StopAsync (if it is not
        // called directly) still drains the in-flight renewal.
        _renewalCts?.Cancel();
    }

    ~AcmeRenewalService()
    {
        Dispose();
    }

    public void Dispose()
    {
        _renewalCts?.Dispose();
        GC.SuppressFinalize(this);
    }

    [LoggerMessage(LogLevel.Trace, "AcmeRenewalService StartAsync")]
    partial void LogAcmerenewalserviceStartasync();

    [LoggerMessage(LogLevel.Warning, "The LetsEncrypt middleware's background renewal thread is shutting down")]
    partial void LogTheLetsencryptMiddlewareSBackgroundRenewalThreadIsShuttingDown();

    [LoggerMessage(LogLevel.Information, "Successfully built certificate chain")]
    partial void LogSuccessfullyBuiltCertificateChain();

    [LoggerMessage(LogLevel.Warning, "Was not able to build certificate chain. This can cause an outage of your app.")]
    partial void LogWasNotAbleToBuildCertificateChainThisCanCauseAnOutageOfYourApp();

    [LoggerMessage(LogLevel.Trace, "AcmeRenewalService - timer callback starting")]
    partial void LogAcmerenewalserviceTimerCallbackStarting();

    [LoggerMessage(LogLevel.Warning, "Exception occurred renewing certificates: '{Message}'")]
    partial void LogExceptionOccurredRenewingCertificatesMessage(Exception e, string message);

    [LoggerMessage(LogLevel.Information, "Renewed ACME certificate for route {RouteId} with status {Status}")]
    partial void LogRenewedRoute(string routeId, CertificateRenewalStatus status);

    [LoggerMessage(LogLevel.Warning, "Renewal failed for route {RouteId}")]
    partial void LogRenewalFailedForRoute(string routeId, Exception exception);
}
