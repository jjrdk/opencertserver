namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using CertesSlim;
using Microsoft.Extensions.Logging;

public sealed partial class PersistenceService : IPersistenceService
{
    //private const string DnsChallengeNameFormat = "_acme-challenge.{0}";
    //private const string WildcardRegex = "^\\*\\.";

    private readonly IEnumerable<ICertificatePersistenceStrategy> _certificatePersistenceStrategies;
    private readonly IChallengePersistenceStrategy[] _challengePersistenceStrategies;

    private readonly ILogger<PersistenceService> _logger;

    public PersistenceService(
        IEnumerable<ICertificatePersistenceStrategy> certificatePersistenceStrategies,
        IEnumerable<IChallengePersistenceStrategy> challengePersistenceStrategies,
        ILogger<PersistenceService> logger)
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
        LogCertificatePersistedForLaterUse();
    }

    public async Task PersistChallenges(ChallengeDto[] challenges)
    {
        LogUsingStrategiesForPersistingChallenge(string.Join(", ", _challengePersistenceStrategies));
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
        LogPersistingTypeCertificateThroughStrategies(persistenceType);

        var tasks = strategies.Select(x => x.Persist(persistenceType, certificate));
        await Task.WhenAll(tasks);
    }

    private async Task PersistChallenges(
        ChallengeDto[] challenges,
        IChallengePersistenceStrategy[] strategies)
    {
        LogPersistingChallengesChallengesThroughStrategies(challenges);

        if (strategies.Length == 0)
        {
            LogThereAreNoChallengesPersistenceStrategiesChallengesWillNotBeStored();
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

        LogDidNotFindSiteCertificateWithStrategiesStrategies(string.Join(",", _certificatePersistenceStrategies));
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

        LogDidNotFindAccountCertificateWithStrategiesStrategies(string.Join(",", _certificatePersistenceStrategies));
        return null;
    }

    public async Task<ChallengeDto[]> GetPersistedChallenges()
    {
        var challenges = await GetPersistedChallengesAsync(_challengePersistenceStrategies);
        return challenges.ToArray();
    }

    private async Task<IEnumerable<ChallengeDto>> GetPersistedChallengesAsync(
        IChallengePersistenceStrategy[] strategies)
    {
        var result = new List<ChallengeDto>();
        foreach (var strategy in strategies)
        {
            result.AddRange(await strategy.Retrieve());
        }

        if (result.Count == 0)
        {
            LogThereAreNoPersistedChallengesFromStrategiesStrategies(string.Join(",", strategies));
        }
        else
        {
            LogRetrievedChallengesChallengesFromPersistenceStrategies(result);
        }

        return result;
    }

    private async Task DeleteChallengesAsync(
        ChallengeDto[] challenges,
        IEnumerable<IChallengePersistenceStrategy> strategies)
    {
        LogDeletingChallengesChallengesThroughStrategies(challenges);

        var tasks = strategies.Select(x => x.Delete(challenges));

        await Task.WhenAll(tasks);
    }

    [LoggerMessage(LogLevel.Information, "Certificate persisted for later use")]
    partial void LogCertificatePersistedForLaterUse();

    [LoggerMessage(LogLevel.Trace, "Using ({Strategies}) for persisting challenge")]
    partial void LogUsingStrategiesForPersistingChallenge(string strategies);

    [LoggerMessage(LogLevel.Trace, "Persisting {Type} certificate through strategies")]
    partial void LogPersistingTypeCertificateThroughStrategies(CertificateType type);

    [LoggerMessage(LogLevel.Trace, "Persisting challenges ({Challenges}) through strategies")]
    partial void LogPersistingChallengesChallengesThroughStrategies(IEnumerable<ChallengeDto> challenges);

    [LoggerMessage(LogLevel.Warning, "There are no challenges persistence strategies - challenges will not be stored")]
    partial void LogThereAreNoChallengesPersistenceStrategiesChallengesWillNotBeStored();

    [LoggerMessage(LogLevel.Trace, "Did not find site certificate with strategies {strategies}.")]
    partial void LogDidNotFindSiteCertificateWithStrategiesStrategies(string strategies);

    [LoggerMessage(LogLevel.Trace, "Did not find account certificate with strategies {strategies}.")]
    partial void LogDidNotFindAccountCertificateWithStrategiesStrategies(string strategies);

    [LoggerMessage(LogLevel.Warning, "There are no persisted challenges from strategies {strategies}")]
    partial void LogThereAreNoPersistedChallengesFromStrategiesStrategies(string strategies);

    [LoggerMessage(LogLevel.Trace, "Retrieved challenges {challenges} from persistence strategies")]
    partial void LogRetrievedChallengesChallengesFromPersistenceStrategies(List<ChallengeDto> challenges);

    [LoggerMessage(LogLevel.Trace, "Deleting challenges {challenges} through strategies.")]
    partial void LogDeletingChallengesChallengesThroughStrategies(IEnumerable<ChallengeDto> challenges);
}
