namespace OpenCertServer.Acme.AspNetClient.Persistence
{
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public interface IChallengePersistenceStrategy
	{
		/// <summary>
		/// The async method to use for persisting a challenge.
		/// </summary>
		Task Persist(IEnumerable<ChallengeDto> challenges);

		/// <summary>
		/// The async method to use for persisting a challenge.
		/// </summary>
		Task<IEnumerable<ChallengeDto>> Retrieve();

		/// <summary>
		/// Optional. The async method to use for deleting a challenge after validation has completed.
		/// </summary>
		Task Delete(IEnumerable<ChallengeDto> challenges);
	}
}
