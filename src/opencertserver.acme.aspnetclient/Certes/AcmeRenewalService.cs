namespace OpenCertServer.Acme.AspNetClient.Certes;

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Certificates;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OpenCertServer.Acme.Abstractions.Acme;
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

    private Timer? _timer;

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

        // Initial issuance for every registered route, isolated so one failure does not block the others.
       await RunAllRoutesOnce(_options.AccountPassword).ConfigureAwait(false);

        _timer = new Timer(_ => RunOnceWithErrorHandling().GetAwaiter().GetResult(), null, Timeout.InfiniteTimeSpan,
            TimeSpan.FromHours(1));

         _lifetime.ApplicationStarted.Register(OnApplicationStarted);
     }

    public async Task StopAsync(CancellationToken cancellationToken)
     {
      LogTheLetsencryptMiddlewareSBackgroundRenewalThreadIsShuttingDown();
        _timer?.Change(Timeout.Infinite, 0);

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

    public async Task RunAllRoutesOnce(string password)
     {
      if (_semaphoreSlim.CurrentCount == 0)
          {
          return;
          }

      await _semaphoreSlim.WaitAsync().ConfigureAwait(false);
        try
             {
            var routes = _routeScope.GetRoutes(_routeConfigurationSource);

             foreach (var route in routes)
                 {
                 try
                      {
                     var current = _routeScope.GetCertificate(route.RouteId);
                       var outcome = await _certificateProvider.RenewCertificateIfNeeded(
                             password, route.RouteId, route.Hosts, current).ConfigureAwait(false);
                         ApplyOutcome(route.RouteId, outcome);
                       await WarmChain(outcome).ConfigureAwait(false);
                       await FireRenewalSucceededHooks(outcome).ConfigureAwait(false);
                       LogRenewedRoute(route.RouteId, outcome.Status);
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
        catch (Exception ex)
            {
            await FireExceptionHooks(ex).ConfigureAwait(false);
               throw;
             }
        finally
             {
            _semaphoreSlim.Release();
             }
      }

      private void ApplyOutcome(string routeId, CertificateRenewalResult result)
         {
       _routeScope.SetCertificate(routeId, result.Certificate);
            // The default-route in-memory leaf is served for unmatched SNI hosts; keep it in sync
             // only when the default route itself is renewed.
         if (string.Equals(routeId, AcmeRouteConstants.DefaultRouteId, StringComparison.Ordinal))
               {
              _routeScope.SetCertificate(AcmeRouteConstants.DefaultRouteId, result.Certificate);
                }
            }

      private async Task WarmChain(CertificateRenewalResult outcome)
      {
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

     private async Task RunOnceWithErrorHandling()
     {
      try
          {
          LogAcmerenewalserviceTimerCallbackStarting();
          await RunAllRoutesOnce(_options.AccountPassword).ConfigureAwait(false);
            _timer?.Change(TimeSpan.FromHours(1), TimeSpan.FromHours(1));
          }
      catch (Exception e) when (_options.RenewalFailMode != RenewalFailMode.Unhandled)
          {
          LogExceptionOccurredRenewingCertificatesMessage(e, e.Message);
          if (_options.RenewalFailMode == RenewalFailMode.LogAndRetry)
               {
                _timer?.Change(TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
                }
          }
     }

     private void OnApplicationStarted()
     {
      LogAcmerenewalserviceApplicationStarted();
        _timer?.Change(_options.RenewalServiceStartupDelay, TimeSpan.FromHours(1));
     }

       ~AcmeRenewalService()
     {
      Dispose();
     }

     public void Dispose()
     {
         _timer?.Dispose();
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

        [LoggerMessage(LogLevel.Information, "AcmeRenewalService - Application started")]
     partial void LogAcmerenewalserviceApplicationStarted();

        [LoggerMessage(LogLevel.Information, "Renewed ACME certificate for route {RouteId} with status {Status}")]
     partial void LogRenewedRoute(string routeId, CertificateRenewalStatus status);

        [LoggerMessage(LogLevel.Warning, "Renewal failed for route {RouteId}")]
     partial void LogRenewalFailedForRoute(string routeId, Exception exception);
}
