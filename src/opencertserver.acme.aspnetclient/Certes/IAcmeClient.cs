namespace OpenCertServer.Acme.AspNetClient.Certes;

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

public interface IAcmeClient
{
    Task<PlacedOrder> PlaceOrder(params string[] domains);

    Task<X509Certificate2> FinalizeOrder(PlacedOrder placedOrder, string password = "");
}
