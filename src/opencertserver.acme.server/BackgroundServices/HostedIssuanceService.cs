namespace OpenCertServer.Acme.Server.BackgroundServices
{
    using Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;
    using OpenCertServer.Acme.Abstractions.Workers;

    public class HostedIssuanceService : TimedHostedService
    {
        private readonly IOptions<ACMEServerOptions> _options;

        public HostedIssuanceService(IOptions<ACMEServerOptions> options, 
            IServiceProvider services, ILogger<TimedHostedService> logger)
            : base(services, logger)
        {
            _options = options;
        }

        protected override bool EnableService
        {
            get { return _options.Value.HostedWorkers.EnableIssuanceService == true; }
        }

        protected override TimeSpan TimerInterval
        {
            get { return TimeSpan.FromSeconds(_options.Value.HostedWorkers!.ValidationCheckInterval); }
        }

        protected override async Task DoWork(IServiceProvider services, CancellationToken cancellationToken)
        {
            var issuanceWorker = services.GetRequiredService<IIssuanceWorker>();
            await issuanceWorker.RunAsync(cancellationToken);
        }
    }
}
