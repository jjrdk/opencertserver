namespace OpenCertServer.Acme.AspNetClient.Persistence
{
    using System.Threading.Tasks;
    using Certificates;
    using global::Certes;

    public interface IPersistenceService
	{
		Task<IKey?> GetPersistedAccountCertificate();
		Task<ChallengeDto[]> GetPersistedChallenges();
		Task<IAbstractCertificate?> GetPersistedSiteCertificate();
		Task PersistAccountCertificate(IKey certificate);
		Task PersistChallenges(ChallengeDto[] challenges);
		Task PersistSiteCertificate(IPersistableCertificate certificate);
		Task DeleteChallenges(ChallengeDto[] challenges);
	}
}