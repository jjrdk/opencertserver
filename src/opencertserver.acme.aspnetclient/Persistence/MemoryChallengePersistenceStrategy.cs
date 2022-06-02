namespace OpenCertServer.Acme.AspNetClient.Persistence
{
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;

    public class MemoryChallengePersistenceStrategy : IChallengePersistenceStrategy
	{
		private IEnumerable<ChallengeDto> _challenges;

		public MemoryChallengePersistenceStrategy()
		{
			_challenges = new List<ChallengeDto>();
		}

		public Task Delete(IEnumerable<ChallengeDto> challenges)
		{
			_challenges = _challenges
				.Where(x =>
					challenges.All(y => y.Token != x.Token))
				.ToList();

			return Task.CompletedTask;
		}

		public Task Persist(IEnumerable<ChallengeDto> challenges)
		{
			_challenges = challenges;

			return Task.CompletedTask;
		}

		public Task<IEnumerable<ChallengeDto>> Retrieve()
		{
			return Task.FromResult(_challenges);
		}

		public override string ToString()
		{
			return $"MemoryChallengePersistence: Content {string.Join(",", _challenges)}";
		}
	}
}
