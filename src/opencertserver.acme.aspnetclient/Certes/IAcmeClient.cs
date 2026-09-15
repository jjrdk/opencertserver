namespace OpenCertServer.Acme.AspNetClient.Certes;

using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

public interface IAcmeClient
{
    Task<PlacedOrder> PlaceOrder(string[] domains);

    /// <summary>
    /// Finalizes an order and returns the issued leaf certificate, the PEM-encoded leaf private key
    /// that was used to sign the CSR, and the full <see cref="X509Certificate2Collection"/> (leaf
    /// followed by issuers) so the caller can persist a real chain. When
    /// <paramref name="existingKeyPem"/> is supplied (a route's persisted key) it is reused so
    /// repeated renewals of the same route keep a stable public key; otherwise a fresh key is
    /// generated.
    /// </summary>
    Task<(X509Certificate2 Certificate, string KeyPem, X509Certificate2Collection Collection)> FinalizeOrder(
        PlacedOrder placedOrder,
        string password = "",
        string? existingKeyPem = null);
}
