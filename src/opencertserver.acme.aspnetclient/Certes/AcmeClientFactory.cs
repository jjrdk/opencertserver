namespace OpenCertServer.Acme.AspNetClient.Certes
{
    using System.Threading.Tasks;
    using global::Certes;
    using Microsoft.Extensions.Logging;
    using Persistence;

    public class AcmeClientFactory : IAcmeClientFactory
    {
        private readonly AcmeOptions _options;
        private readonly ILoggerFactory _loggerFactory;
        private readonly ILogger _logger;
        private readonly IPersistenceService _persistenceService;
        private AcmeContext? _acme;
        
        public AcmeClientFactory(
            IPersistenceService persistenceService,
            AcmeOptions options,
            ILoggerFactory loggerFactory)
        {
            _options = options;
            _loggerFactory = loggerFactory;
            _persistenceService = persistenceService;
            _logger = loggerFactory.CreateLogger<AcmeClientFactory>();
        }

        public async Task<IAcmeClient> GetClient()
        {
            var context = await GetContext();
            var logger = _loggerFactory.CreateLogger<AcmeClient>();
            return new AcmeClient(context, _options, logger);
        }

        private async Task<IAcmeContext> GetContext()
        {
            if (_acme != null)
            {
                return _acme;
            }

            var existingAccountKey = await _persistenceService.GetPersistedAccountCertificate();
            if (existingAccountKey != null)
            {
                _logger.LogDebug("Using existing LetsEncrypt account.");
                var acme = new AcmeContext(_options.AcmeServerUri, existingAccountKey);
                await acme.Account();
                return _acme = acme;
            }
            else
            {
                _logger.LogDebug("Creating LetsEncrypt account with email {EmailAddress}.", _options.Email);
                var acme = new AcmeContext(_options.AcmeServerUri);
                await acme.NewAccount(_options.Email, true);
                await _persistenceService.PersistAccountCertificate(acme.AccountKey);
                return _acme = acme;
            }
        }
    }
}