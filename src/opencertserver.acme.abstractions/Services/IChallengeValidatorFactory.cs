namespace OpenCertServer.Acme.Abstractions.Services;

using Model;

/// <summary>
/// Defines a factory for obtaining challenge validators for ACME challenges.
/// </summary>
public interface IChallengeValidatorFactory
{
    /// <summary>
    /// Gets a validator for the specified challenge.
    /// </summary>
    /// <param name="challenge">The challenge to validate.</param>
    /// <returns>An <see cref="IValidateChallenges"/> instance for the challenge.</returns>
    IValidateChallenges GetValidator(Challenge challenge);
}
