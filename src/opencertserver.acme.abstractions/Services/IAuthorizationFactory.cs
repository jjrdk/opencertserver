namespace OpenCertServer.Acme.Abstractions.Services
{
    using Model;

    public interface IAuthorizationFactory
    {
        void CreateAuthorizations(Order order);
    }
}
