namespace OpenCertServer.Acme.Abstractions.Services
{
    using Model;

    public interface IChallengeValidatorFactory
    {
        IValidateChallenges GetValidator(Challenge challenge);
    }
}
