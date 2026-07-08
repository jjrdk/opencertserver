using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Attestation.Tests.Mocks;

public class MockProvider : IAttestationProvider
{
    public string VendorName { get; init; } = "";
    public Task<string> GetDeviceIdAsync() => Task.FromResult("mock-id");
    public Task<X509Certificate2> RetrieveDeviceCertificateAsync(string deviceId) => throw new NotImplementedException();
    public Task<byte[]> GenerateAndSignQuoteAsync(X509Certificate2 cert, byte[] nonce) => throw new NotImplementedException();
}

/// <summary>
/// Reusable HTTP message handler stub for tests.
/// </summary>
public sealed class MockHttpHandler : HttpMessageHandler
{
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _handler;

    public MockHttpHandler(HttpResponseMessage response)
        : this((_, _) => Task.FromResult(response)) { }

    public MockHttpHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> handler)
        => _handler = handler;

    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => _handler(request, cancellationToken);
}

/// <summary>
/// Certificate factory helpers shared across test step definitions.
/// </summary>
public static class TestCertificateFactory
{
    public static X509Certificate2 CreateSelfSignedCert(string dn)
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(new X500DistinguishedName(dn), rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }

    /// <summary>
    /// Creates a leaf certificate signed by the given CA key/cert.
    /// </summary>
    public static X509Certificate2 CreateSignedCert(string leafDn, X509Certificate2 caCert, RSA caKey)
    {
        using var leafKey = RSA.Create(2048);
        var req = new CertificateRequest(new X500DistinguishedName(leafDn), leafKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var cert = req.Create(caCert, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1),
            Guid.NewGuid().ToByteArray());
        return cert.CopyWithPrivateKey(leafKey);
    }
}
