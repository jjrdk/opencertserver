using CertesSlim.Extensions;

namespace OpenCertServer.Acme.AspNetClient.Certes;

using System.Threading.Tasks;
using CertesSlim;
using global::CertesSlim.Acme;
using Microsoft.Extensions.Logging;
using Persistence;

public sealed class AcmeClientFactory : IAcmeClientFactory
{
    private readonly AcmeOptions _options;
    private readonly HttpClient _httpClient;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;
    private readonly IPersistenceService _persistenceService;
    private AcmeContext? _acme;

    public AcmeClientFactory(
        IPersistenceService persistenceService,
        AcmeOptions options,
        HttpClient httpClient,
        ILoggerFactory loggerFactory)
    {
        _options = options;
        _httpClient = httpClient;
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
        var acme = new AcmeContext(
            _options.AcmeServerUri,
            existingAccountKey,
            new AcmeHttpClient(_options.AcmeServerUri, _httpClient));
        if (existingAccountKey != null)
        {
            _logger.LogDebug("Using existing ACME account");

            await acme.Account();
            return _acme = acme;
        }

        _logger.LogDebug("Creating ACME account with email {EmailAddress}", _options.Email);

        await acme.NewAccount(_options.Email, true);
        await _persistenceService.PersistAccountCertificate(acme.AccountKey);
        return _acme = acme;
    }
}
