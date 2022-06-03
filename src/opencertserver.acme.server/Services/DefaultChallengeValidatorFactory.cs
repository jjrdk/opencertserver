namespace OpenCertServer.Acme.Server.Services
{
    using System;
    using Abstractions.Model;
    using Abstractions.Services;

    public class DefaultChallengeValidatorFactory : IChallengeValidatorFactory
    {
        private readonly IHttp01ChallengeValidator _http01ChallengeValidator;
        private readonly IDns01ChallengeValidator _dns01ChallengeValidator;

        public DefaultChallengeValidatorFactory(IHttp01ChallengeValidator http01ChallengeValidator, IDns01ChallengeValidator dns01ChallengeValidator)
        {
            _http01ChallengeValidator = http01ChallengeValidator;
            _dns01ChallengeValidator = dns01ChallengeValidator;
        }

        public IChallengeValidator GetValidator(Challenge challenge)
        {
            if (challenge is null)
            {
                throw new ArgumentNullException(nameof(challenge));
            }

            IChallengeValidator validator = challenge.Type switch
            {
                ChallengeTypes.Http01 => _http01ChallengeValidator,
                ChallengeTypes.Dns01 => _dns01ChallengeValidator,
                _ => throw new InvalidOperationException("Unknown Challenge Type")
            };

            return validator;
        }
    }
}
