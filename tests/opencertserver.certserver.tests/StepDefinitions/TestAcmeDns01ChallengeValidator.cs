namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using Acme.Abstractions.Model;
using Acme.Abstractions.Services;
using Acme.Server.Services;

internal sealed class TestAcmeDns01ChallengeValidator : TokenChallengeValidator, IValidateDns01Challenges
{
    private readonly TestAcmeChallengeValidationState _state;

    public TestAcmeDns01ChallengeValidator(TestAcmeChallengeValidationState state)
    {
        _state = state;
    }

    public override Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
        Challenge challenge,
        Account account,
        CancellationToken cancellationToken)
    {
        _state.LastValidatedChallengeType = challenge.Type;
        if (_state.DnsShouldSucceed)
        {
            return Task.FromResult((true, (AcmeError?)null));
        }

        return Task.FromResult<(bool IsValid, AcmeError? error)>((false,
            new AcmeError(_state.FailureType, _state.FailureDetail, challenge.Authorization.Identifier)));
    }

    protected override Task<(List<string>? Contents, AcmeError? Error)> LoadChallengeResponse(Challenge challenge, CancellationToken cancellationToken)
        => throw new NotImplementedException();

    protected override string GetExpectedContent(Challenge challenge, Account account)
        => throw new NotImplementedException();
}


