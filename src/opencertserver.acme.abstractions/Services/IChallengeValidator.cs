namespace OpenCertServer.Acme.Abstractions.Services
{
    using System.Threading;
    using System.Threading.Tasks;
    using Model;

    public interface IChallengeValidator
    {
        Task<(bool IsValid, AcmeError? error)> ValidateChallengeAsync(Challenge challenge, Account account, CancellationToken cancellationToken);
    }
}
