namespace OpenCertServer.Acme.AspNetClient.Certes;

using System.Threading.Tasks;

public interface IAcmeClient
{
    Task<PlacedOrder> PlaceOrder(params string[] domains);

    Task<PfxCertificate> FinalizeOrder(PlacedOrder placedOrder);
}
