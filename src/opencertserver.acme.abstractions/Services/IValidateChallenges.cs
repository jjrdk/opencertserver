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
