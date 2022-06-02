namespace OpenCertServer.Acme.Server.Services;

using Abstractions.Model;
using Abstractions.Services;

public class PassAllChallengeValidator : TokenChallengeValidator, IHttp01ChallengeValidator
{
    /// <inheritdoc />
    public override Task<(bool IsValid, AcmeError? error)> ValidateChallenge(Challenge challenge, Account account, CancellationToken cancellationToken)
    {
        return Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    /// <inheritdoc />
    protected override Task<(List<string>? Contents, AcmeError? Error)> LoadChallengeResponse(Challenge challenge, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    /// <inheritdoc />
    protected override string GetExpectedContent(Challenge challenge, Account account)
    {
        throw new NotImplementedException();
    }
}