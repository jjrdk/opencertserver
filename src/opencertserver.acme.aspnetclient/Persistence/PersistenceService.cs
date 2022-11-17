namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using global::Certes;
using Microsoft.Extensions.Logging;

public sealed class PersistenceService : IPersistenceService
{
    //private const string DnsChallengeNameFormat = "_acme-challenge.{0}";
    //private const string WildcardRegex = "^\\*\\.";

    private readonly IEnumerable<ICertificatePersistenceStrategy> _certificatePersistenceStrategies;
    private readonly IChallengePersistenceStrategy[] _challengePersistenceStrategies;

    private readonly ILogger<IPersistenceService> _logger;

    public PersistenceService(
        IEnumerable<ICertificatePersistenceStrategy> certificatePersistenceStrategies,
        IEnumerable<IChallengePersistenceStrategy> challengePersistenceStrategies,
        ILogger<IPersistenceService> logger)
    {
        _certificatePersistenceStrategies = certificatePersistenceStrategies;
        _challengePersistenceStrategies = challengePersistenceStrategies.ToArray();
        _logger = logger;
    }

    public async Task PersistAccountCertificate(IKey certificate)
    {
        await PersistCertificate(
            CertificateType.Account,
            Encoding.UTF8.GetBytes(certificate.ToPem()),
            _certificatePersistenceStrategies);
    }

    public async Task PersistSiteCertificate(
        X509Certificate2 certificate,
        CancellationToken cancellationToken = default)
    {
        await PersistCertificate(CertificateType.Site, certificate.RawData, _certificatePersistenceStrategies);
        _logger.LogInformation("Certificate persisted for later use.");
    }

    public async Task PersistChallenges(ChallengeDto[] challenges)
    {
        _logger.LogTrace("Using ({Strategies}) for persisting challenge", _challengePersistenceStrategies);
        await PersistChallenges(challenges, _challengePersistenceStrategies);
    }

    public async Task DeleteChallenges(ChallengeDto[] challenges)
    {
        await DeleteChallengesAsync(challenges, _challengePersistenceStrategies);
    }

    //private string GetChallengeDnsName(string domain)
    //{
    //	var dnsName = Regex.Replace(domain, WildcardRegex, String.Empty);
    //	dnsName = String.Format(DnsChallengeNameFormat, dnsName);

    //	return dnsName;
    //}

    private async Task PersistCertificate(
        CertificateType persistenceType,
        byte[] certificate,
        IEnumerable<ICertificatePersistenceStrategy> strategies)
    {
        _logger.LogTrace("Persisting {type} certificate through strategies", persistenceType);

        var tasks = strategies.Select(x => x.Persist(persistenceType, certificate));
        await Task.WhenAll(tasks);
    }

    private async Task PersistChallenges(
        IEnumerable<ChallengeDto> challenges,
        IChallengePersistenceStrategy[] strategies)
    {
        _logger.LogTrace("Persisting challenges ({challenges}) through strategies.", challenges);

        if (strategies.Length == 0)
        {
            _logger.LogWarning("There are no challenges persistence strategies - challenges will not be stored");
        }

        var tasks = strategies.Select(x => x.Persist(challenges));

        await Task.WhenAll(tasks);
    }

    public async Task<X509Certificate2?> GetPersistedSiteCertificate(CancellationToken cancellationToken = default)
    {
        foreach (var strategy in _certificatePersistenceStrategies)
        {
            var certificate = await strategy.RetrieveSiteCertificate();
            if (certificate != null)
            {
                return certificate;
            }
        }

        _logger.LogTrace(
            "Did not find site certificate with strategies {strategies}.",
            string.Join(",", _certificatePersistenceStrategies));
        return null;
    }

    public async Task<IKey?> GetPersistedAccountCertificate()
    {
        foreach (var strategy in _certificatePersistenceStrategies)
        {
            var certificate = await strategy.RetrieveAccountCertificate();
            if (certificate != null)
            {
                return KeyFactory.FromPem(Encoding.UTF8.GetString(certificate));
            }
        }

        _logger.LogTrace(
            "Did not find account certificate with strategies {strategies}.",
            string.Join(",", _certificatePersistenceStrategies));
        return null;
    }

    public async Task<ChallengeDto[]> GetPersistedChallenges()
    {
        var challenges = await GetPersistedChallengesAsync(_challengePersistenceStrategies);
        return challenges.ToArray();
    }

    private async Task<IEnumerable<ChallengeDto>> GetPersistedChallengesAsync(
        IEnumerable<IChallengePersistenceStrategy> strategies)
    {
        var result = new List<ChallengeDto>();
        foreach (var strategy in strategies)
        {
            result.AddRange(await strategy.Retrieve());
        }

        if (!result.Any())
        {
            _logger.LogWarning(
                "There are no persisted challenges from strategies {strategies}",
                string.Join(",", strategies));
        }
        else
        {
            _logger.LogTrace("Retrieved challenges {challenges} from persistence strategies", result);
        }

        return result;
    }

    private async Task DeleteChallengesAsync(
        IEnumerable<ChallengeDto> challenges,
        IEnumerable<IChallengePersistenceStrategy> strategies)
    {
        _logger.LogTrace("Deleting challenges {challenges} through strategies.", challenges);

        var tasks = strategies.Select(x => x.Delete(challenges));

        await Task.WhenAll(tasks);
    }
}