namespace OpenCertServer.Acme.Server.Services;

using System;
using Abstractions.Model;
using Abstractions.Services;

public sealed class DefaultChallengeValidatorFactory : IChallengeValidatorFactory
{
    private readonly IValidateHttp01Challenges _validateHttp01Challenges;
    private readonly IValidateDns01Challenges _validateDns01Challenges;

    public DefaultChallengeValidatorFactory(IValidateHttp01Challenges validateHttp01Challenges, IValidateDns01Challenges validateDns01Challenges)
    {
        _validateHttp01Challenges = validateHttp01Challenges;
        _validateDns01Challenges = validateDns01Challenges;
    }

    public IValidateChallenges GetValidator(Challenge challenge)
    {
        if (challenge is null)
        {
            throw new ArgumentNullException(nameof(challenge));
        }

        IValidateChallenges validator = challenge.Type switch
        {
            ChallengeTypes.Http01 => _validateHttp01Challenges,
            ChallengeTypes.Dns01 => _validateDns01Challenges,
            _ => throw new InvalidOperationException("Unknown Challenge Type")
        };

        return validator;
    }
}