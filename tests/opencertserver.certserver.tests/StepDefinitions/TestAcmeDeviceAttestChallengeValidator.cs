namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Threading;
using System.Threading.Tasks;
using Acme.Abstractions.Model;
using Acme.Abstractions.Services;

/// <summary>
/// Test stub for device-attest-01 challenge validation.
/// Always succeeds in the certserver integration test environment.
/// </summary>
internal sealed class TestAcmeDeviceAttestChallengeValidator : IValidateDeviceAttestChallenges
{
    public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
        Challenge challenge,
        Account account,
        CancellationToken cancellationToken)
        => Task.FromResult<(bool IsValid, AcmeError? error)>((true, null));
}
