using System.Text.Json;

namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

public sealed class FileChallengePersistenceStrategy : IChallengePersistenceStrategy
{
    private readonly string _relativeFilePath;

    public FileChallengePersistenceStrategy(string relativeFilePath)
    {
        _relativeFilePath = relativeFilePath;
    }

    public async Task Delete(IEnumerable<ChallengeDto> challenges)
    {
        var persistedChallenges = await Retrieve();
        var challengesToPersist = persistedChallenges
            .Where(x =>
                challenges.All(y => y.Token != x.Token))
            .ToList();

        await Persist(challengesToPersist);
    }

    public Task Persist(IEnumerable<ChallengeDto> challenges)
    {
        var json = JsonSerializer.Serialize(challenges.ToArray(), AcmeClientSerializerContext.Default.ChallengeDtoArray);

        var bytes = Encoding.UTF8.GetBytes(json);

        return File.WriteAllBytesAsync(GetChallengesStorePath(), bytes);
    }

    public async Task<IEnumerable<ChallengeDto>> Retrieve()
    {
        if (!File.Exists(GetChallengesStorePath()))
        {
            return [];
        }

        var bytes = await File.ReadAllBytesAsync(GetChallengesStorePath());
        var json = Encoding.UTF8.GetString(bytes);
        var challenges = JsonSerializer.Deserialize<ChallengeDto[]>(json, AcmeClientSerializerContext.Default.ChallengeDtoArray);

        return challenges ?? [];
    }

    private string GetChallengesStorePath()
    {
        return $"{_relativeFilePath}_Challenges";
    }
}
