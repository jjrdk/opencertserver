namespace OpenCertServer.Acme.AspNetClient.Certes;

using System.Threading.Tasks;

public interface IAcmeClientFactory
{
    Task<IAcmeClient> GetClient();
}