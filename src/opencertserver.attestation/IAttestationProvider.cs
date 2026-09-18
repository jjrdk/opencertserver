namespace OpenCertServer.Attestation;

using System.Security.Cryptography.X509Certificates;

public interface IAttestationProvider
{
    string VendorName { get; }
    Task<string> GetDeviceIdAsync();
    Task<X509Certificate2> RetrieveDeviceCertificateAsync(string deviceId);
    Task<byte[]> GenerateAndSignQuoteAsync(X509Certificate2 cert, byte[] nonce);
}
