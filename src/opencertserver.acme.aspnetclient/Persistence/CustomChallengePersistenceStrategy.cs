namespace OpenCertServer.Acme.AspNetClient.Persistence
{
    using System;
    using System.Collections.Generic;
    using System.Threading.Tasks;

    public sealed class CustomChallengePersistenceStrategy : IChallengePersistenceStrategy
    {
        private readonly Func<IEnumerable<ChallengeDto>, Task> _persist;
        private readonly Func<IEnumerable<ChallengeDto>, Task> _delete;
        private readonly Func<Task<IEnumerable<ChallengeDto>>> _retrieve;

        public CustomChallengePersistenceStrategy(
            Func<IEnumerable<ChallengeDto>, Task> persist,
            Func<Task<IEnumerable<ChallengeDto>>> retrieve,
            Func<IEnumerable<ChallengeDto>, Task> delete)
        {
            _persist = persist;
            _delete = delete;
            _retrieve = retrieve;
        }

        public Task Persist(IEnumerable<ChallengeDto> challenges)
        {
            return _persist(challenges);
        }

        public Task<IEnumerable<ChallengeDto>> Retrieve()
        {
            return _retrieve();
        }

        public Task Delete(IEnumerable<ChallengeDto> challenges)
        {
            return _delete(challenges);
        }
    }
}
