
namespace OpenCertServer.Acme.AspNetClient.Certes
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;
    using System.Threading.Tasks;
    using Certificates;
    using Microsoft.Extensions.Hosting;
    using Microsoft.Extensions.Logging;
    using static Certificates.CertificateRenewalStatus;

    public class AcmeRenewalService : IAcmeRenewalService
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
            ILogger<IAcmeRenewalService> logger,
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

            _logger.LogTrace("AcmeRenewalService StartAsync");

            foreach (var lifecycleHook in _lifecycleHooks)
            {
                await lifecycleHook.OnStart();
            }

            _timer = new Timer(async state => await RunOnceWithErrorHandling(), null, Timeout.InfiniteTimeSpan, TimeSpan.FromHours(1));

            _lifetime.ApplicationStarted.Register(OnApplicationStarted);
        }

        public async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogWarning("The LetsEncrypt middleware's background renewal thread is shutting down.");
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
                    using var chain = new X509Chain
                    {
                        ChainPolicy =
                        {
                            RevocationMode = X509RevocationMode.NoCheck
                        }
                    };

                    if (result.Certificate != null)
                    {
                        if (chain.Build(result.Certificate))
                        {
                            _logger.LogInformation("Successfully built certificate chain");
                        }
                        else
                        {
                            _logger.LogWarning(
                                "Was not able to build certificate chain. This can cause an outage of your app.");
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
                _logger.LogTrace("AcmeRenewalService - timer callback starting");
                await RunOnce();
                _timer?.Change(TimeSpan.FromHours(1), TimeSpan.FromHours(1));
            }
            catch (Exception e) when (_options.RenewalFailMode != RenewalFailMode.Unhandled)
            {
                _logger.LogWarning(e, "Exception occurred renewing certificates: '{Message}'", e.Message);
                if (_options.RenewalFailMode == RenewalFailMode.LogAndRetry)
                {
                    _timer?.Change(TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));
                }
            }
        }

        private void OnApplicationStarted()
        {
            _logger.LogInformation("AcmeRenewalService - Application started");
            _timer?.Change(_options.RenewalServiceStartupDelay, TimeSpan.FromHours(1));
        }

        public void Dispose()
        {
            _timer?.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}