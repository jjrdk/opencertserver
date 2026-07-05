namespace OpenCertServer.Acme.Server.Services;

using System;
using Abstractions.Model;
using Abstractions.Services;

public sealed class DefaultChallengeValidatorFactory : IChallengeValidatorFactory
{
    private readonly IValidateHttp01Challenges _validateHttp01Challenges;
    private readonly IValidateDns01Challenges _validateDns01Challenges;
    private readonly IValidateDeviceAttestChallenges _validateDeviceAttestChallenges;

    public DefaultChallengeValidatorFactory(
        IValidateHttp01Challenges validateHttp01Challenges,
        IValidateDns01Challenges validateDns01Challenges,
        IValidateDeviceAttestChallenges validateDeviceAttestChallenges)
    {
        _validateHttp01Challenges = validateHttp01Challenges;
        _validateDns01Challenges = validateDns01Challenges;
        _validateDeviceAttestChallenges = validateDeviceAttestChallenges;
    }

    public IValidateChallenges GetValidator(Challenge challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);

        IValidateChallenges validator = challenge.Type switch
        {
            ChallengeTypes.Http01 => _validateHttp01Challenges,
            ChallengeTypes.Dns01 => _validateDns01Challenges,
            ChallengeTypes.DeviceAttest01 => _validateDeviceAttestChallenges,
            _ => throw new InvalidOperationException("Unknown Challenge Type")
        };

        return validator;
    }
}