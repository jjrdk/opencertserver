namespace OpenCertServer.Acme.Abstractions.Services
{
    using Model;

    public interface IChallangeValidatorFactory
    {
        IChallengeValidator GetValidator(Challenge challenge);
    }
}
