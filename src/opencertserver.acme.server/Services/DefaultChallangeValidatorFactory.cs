namespace OpenCertServer.Acme.Server.Services
{
    using System;
    using Abstractions.Model;
    using Abstractions.Services;
    using Microsoft.Extensions.DependencyInjection;

    public class DefaultChallangeValidatorFactory : IChallangeValidatorFactory
    {
        private readonly IServiceProvider _services;

        public DefaultChallangeValidatorFactory(IServiceProvider services)
        {
            _services = services;
        }

        public IChallengeValidator GetValidator(Challenge challenge)
        {
            if (challenge is null)
            {
                throw new ArgumentNullException(nameof(challenge));
            }

            IChallengeValidator validator = challenge.Type switch
            {
                ChallengeTypes.Http01 => _services.GetRequiredService<Http01ChallangeValidator>(),
                ChallengeTypes.Dns01 => _services.GetRequiredService<Dns01ChallangeValidator>(),
                _ => throw new InvalidOperationException("Unknown Challenge Type")
            };

            return validator;
        }
    }
}
