namespace OpenCertServer.Attestation.Tests.Mocks;

public class MockProvider : IAttestationProvider
{
    public string VendorName { get; init; } = "";
    public Task<string> GetDeviceIdAsync() => Task.FromResult("mock-id");
    public Task<System.Security.Cryptography.X509Certificates.X509Certificate2> RetrieveDeviceCertificateAsync(string deviceId) => throw new NotImplementedException();
    public Task<byte[]> GenerateAndSignQuoteAsync(System.Security.Cryptography.X509Certificates.X509Certificate2 cert, byte[] nonce) => throw new NotImplementedException();
}
