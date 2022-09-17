namespace OpenCertServer.Acme.Server.BackgroundServices
{
    using Abstractions.Workers;
    using Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;
    using Microsoft.Extensions.Options;

    public sealed class HostedValidationService : TimedHostedService
    {
        private readonly IOptions<AcmeServerOptions> _options;

        public HostedValidationService(IOptions<AcmeServerOptions> options, 
            IServiceProvider services, ILogger<TimedHostedService> logger) 
            : base(services, logger)
        {
            _options = options;
        }

        protected override bool EnableService
        {
            get { return _options.Value.HostedWorkers.EnableValidationService; }
        }

        protected override TimeSpan TimerInterval
        {
            get { return TimeSpan.FromSeconds(_options.Value.HostedWorkers.ValidationCheckInterval); }
        }


        protected override async Task DoWork(IServiceProvider services, CancellationToken cancellationToken)
        {
            var validationWorker = services.GetRequiredService<IValidationWorker>();
            await validationWorker.Run(cancellationToken);
        }
    }
}
