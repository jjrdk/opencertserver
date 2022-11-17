namespace OpenCertServer.Acme.Abstractions.Services;

using System.Threading;
using System.Threading.Tasks;
using Model;

public interface IValidateChallenges
{
    Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
        Challenge challenge,
        Account account,
        CancellationToken cancellationToken);
}

public interface IValidateHttp01Challenges : IValidateChallenges
{
}

public interface IValidateDns01Challenges : IValidateChallenges
{
}