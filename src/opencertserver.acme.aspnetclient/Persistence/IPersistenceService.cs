namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CertesSlim;

public interface IPersistenceService
{
    Task<IKey?> GetPersistedAccountCertificate();
    Task<ChallengeDto[]> GetPersistedChallenges();
    Task<X509Certificate2?> GetPersistedSiteCertificate(CancellationToken cancellationToken = default);
    Task PersistAccountCertificate(IKey certificate);
    Task PersistChallenges(ChallengeDto[] challenges);
    Task PersistSiteCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default);
    Task DeleteChallenges(ChallengeDto[] challenges);
}