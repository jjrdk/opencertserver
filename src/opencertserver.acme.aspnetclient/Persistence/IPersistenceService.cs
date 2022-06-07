namespace OpenCertServer.Acme.AspNetClient.Persistence
{
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;
    using global::Certes;

    public interface IPersistenceService
    {
        Task<IKey?> GetPersistedAccountCertificate();
        Task<ChallengeDto[]> GetPersistedChallenges();
        Task<X509Certificate2?> GetPersistedSiteCertificate();
        Task PersistAccountCertificate(IKey certificate);
        Task PersistChallenges(ChallengeDto[] challenges);
        Task PersistSiteCertificate(X509Certificate2 certificate);
        Task DeleteChallenges(ChallengeDto[] challenges);
    }
}