
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

    private Timer? _timer;

    public AcmeRenewalService(
        IProvideCertificates certificateProvider,
        IEnumerable<ICertificateRenewalLifecycleHook> lifecycleHooks,
        IHostApplicationLifetime lifetime,
        ILogger<AcmeRenewalService> logger,
        AcmeOptions options)
    {
        _certificateProvider = certificateProvider;
        _lifecycleHooks = lifecycleHooks;
        _lifetime = lifetime;
        _logger = logger;
        _options = options;
        _semaphoreSlim = new SemaphoreSlim(1);
    }

    internal X509Certificate2? Certificate { get; private set; }

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
            await lifecycleHook.OnStart();
        }

        _timer = new Timer(_ => RunOnceWithErrorHandling().GetAwaiter().GetResult(), null, Timeout.InfiniteTimeSpan, TimeSpan.FromHours(1));

        _lifetime.ApplicationStarted.Register(OnApplicationStarted);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        LogTheLetsencryptMiddlewareSBackgroundRenewalThreadIsShuttingDown();
        _timer?.Change(Timeout.Infinite, 0);

        foreach (var lifecycleHook in _lifecycleHooks)
        {
            await lifecycleHook.OnStop();
        }
    }

    public async Task RunOnce()
    {
        if (_semaphoreSlim.CurrentCount == 0)
        {
            return;
        }

        await _semaphoreSlim.WaitAsync();

        try
        {
            // TODO: set password
            var result = await _certificateProvider.RenewCertificateIfNeeded("TODO",Certificate);

            if (result.Status != Unchanged)
            {
                // Pre-load intermediate certs before exposing certificate to the Kestrel
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

                if (result.Certificate != null)
                {
                    if (chain.Build(result.Certificate))
                    {
                        LogSuccessfullyBuiltCertificateChain();
                    }
                    else
                    {
                        LogWasNotAbleToBuildCertificateChainThisCanCauseAnOutageOfYourApp();
                    }
                }
            }

            Certificate = result.Certificate;

            if (result.Status == Renewed)
            {
                foreach (var lifecycleHook in _lifecycleHooks)
                {
                    await lifecycleHook.OnRenewalSucceeded();
                }
            }
        }
        catch (Exception ex)
        {
            foreach (var lifecycleHook in _lifecycleHooks)
            {
                await lifecycleHook.OnException(ex);
            }

            throw;
        }
        finally
        {
            _semaphoreSlim.Release();
        }
    }

    private async Task RunOnceWithErrorHandling()
    {
        try
        {
            LogAcmerenewalserviceTimerCallbackStarting();
            await RunOnce();
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
}
