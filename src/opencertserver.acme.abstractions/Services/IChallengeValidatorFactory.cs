namespace OpenCertServer.Acme.Abstractions.Services
{
    using Model;

    public interface IChallengeValidatorFactory
    {
        IChallengeValidator GetValidator(Challenge challenge);
    }
}
