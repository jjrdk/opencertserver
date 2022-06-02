namespace OpenCertServer.Acme.Abstractions.Services
{
    using System.Threading;
    using System.Threading.Tasks;
    using Model;

    public interface IChallengeValidator
    {
        Task<(bool IsValid, AcmeError? error)> ValidateChallenge(Challenge challenge, Account account, CancellationToken cancellationToken);
    }

    public interface IHttp01ChallengeValidator : IChallengeValidator { }
    public interface IDns01ChallengeValidator : IChallengeValidator { }
}
