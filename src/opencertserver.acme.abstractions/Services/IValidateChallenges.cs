using CertesSlim.Acme;

namespace OpenCertServer.Acme.Abstractions.Services;

using System.Threading;
using System.Threading.Tasks;
using Model;

/// <summary>
/// Defines a service for validating ACME challenges.
/// </summary>
public interface IValidateChallenges
{
    /// <summary>
    /// The ACME challenge type this validator handles (e.g. <c>dns-01</c>, <c>http-01</c>,
    /// <c>device-attest-01</c> — see <c>CertesSlim.Acme.Resource.ChallengeTypes</c>). The challenge
    /// validator factory routes a <see cref="Challenge"/> to the validator whose <see cref="AppliesTo"/>
    /// matches <see cref="Challenge.Type"/>, which replaces the per-type marker interfaces.
    /// </summary>
    string AppliesTo { get; }

    /// <summary>
    /// Validates the specified challenge for the given account.
    /// </summary>
    /// <param name="challenge">The challenge to validate.</param>
    /// <param name="account">The account associated with the challenge.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A tuple indicating whether the challenge is valid and an optional error.</returns>
    Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
        Challenge challenge,
        Account account,
        CancellationToken cancellationToken);
}
