using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenCertServer.Attestation.Native;

namespace OpenCertServer.Attestation;

/// <summary>
/// Apple Secure Enclave / App Attest provider.
///
/// <para><b>On Apple devices (macOS 11+, iOS 14+)</b>: Generates attestation objects by calling
/// the native DCAppAttestService via <see cref="IAppleAttestNativeInterop"/>. The caller
/// is expected to supply a challenge (<paramref name="nonce"/> in
/// <see cref="GenerateAndSignQuoteAsync"/>) that the SE will bind into the attestation
/// object.</para>
///
/// <para><b>On non-Apple platforms (server-side verification)</b>: The <paramref name="nonce"/>
/// argument to <see cref="GenerateAndSignQuoteAsync"/> must contain the raw CBOR-encoded
/// attestation object received from the iOS/macOS client. The provider forwards it to
/// Apple's verification endpoint and returns the signed response token.</para>
/// </summary>
public sealed class AppleSeProvider : IAttestationProvider
{
    public string VendorName => "Apple";

    private readonly HttpClient _httpClient;
    private readonly ILogger<AppleSeProvider> _logger;
    private readonly IAppleAttestNativeInterop _native;
    private readonly AppleSeOptions _options;

    public AppleSeProvider(
        IHttpClientFactory httpClientFactory,
        ILogger<AppleSeProvider> logger,
        IAppleAttestNativeInterop native,
        IOptions<AttestationOptions> options)
    {
        _httpClient = httpClientFactory.CreateClient(nameof(AppleSeProvider));
        _logger = logger;
        _native = native;
        _options = options.Value.AppleSE;
    }

    /// <summary>
    /// On Apple devices: generates a Secure Enclave key and returns its identifier.
    /// On other platforms: throws <see cref="PlatformNotSupportedException"/> because
    /// key generation must occur on the device itself.
    /// </summary>
    public async Task<string> GetDeviceIdAsync()
    {
        if (!_options.UseDeviceAttestation || !IsApplePlatform())
        {
            throw new PlatformNotSupportedException(
                "Apple Secure Enclave key generation is only available on macOS 11+ or iOS 14+ with " +
                "UseDeviceAttestation = true. On server platforms, the device ID is supplied by the " +
                "client as part of the attestation object.");
        }

        _logger.LogInformation("Generating Secure Enclave key via DCAppAttestService");
        return await _native.GenerateKeyAsync();
    }

    /// <summary>
    /// Apple's App Attest flow does not issue X.509 device certificates in the traditional sense;
    /// the certificate chain is embedded in the CBOR attestation object. This method is a no-op
    /// for Apple and returns an empty placeholder.
    /// </summary>
    public Task<X509Certificate2> RetrieveDeviceCertificateAsync(string deviceId)
    {
        // Apple embeds the certificate chain inside the attestation object itself (attStmt.x5c).
        // There is no separate certificate endpoint to query.
        return Task.FromResult(CreatePlaceholderCert());
    }

    /// <summary>
    /// <b>On Apple devices</b>: <paramref name="nonce"/> is the server challenge (any byte array).
    /// The method hashes it with SHA-256, calls the SE to produce the attestation object,
    /// and returns the raw CBOR bytes to be sent to the server.
    ///
    /// <b>On server (non-Apple)</b>: <paramref name="nonce"/> must be the raw attestation
    /// object bytes received from the iOS/macOS client. The method forwards it to Apple's
    /// verification endpoint and returns the response.
    /// </summary>
    public async Task<byte[]> GenerateAndSignQuoteAsync(X509Certificate2 cert, byte[] nonce)
    {
        if (nonce is null || nonce.Length == 0)
            throw new ArgumentException("Nonce/attestation object must not be empty.", nameof(nonce));

        if (_options.UseDeviceAttestation && IsApplePlatform())
            return await GenerateAttestationOnDeviceAsync(nonce);

        return await VerifyAttestationOnServerAsync(nonce);
    }

    private async Task<byte[]> GenerateAttestationOnDeviceAsync(byte[] challenge)
    {
        _logger.LogInformation("Generating App Attest attestation object on Apple device");
        var keyId = await _native.GenerateKeyAsync();
        var clientDataHash = SHA256.HashData(challenge);
        var attestationObject = await _native.AttestKeyAsync(keyId, clientDataHash);
        _logger.LogInformation("Attestation object generated for key {KeyId}", keyId);
        return attestationObject;
    }

    private async Task<byte[]> VerifyAttestationOnServerAsync(byte[] attestationObject)
    {
        _logger.LogInformation("Forwarding attestation object to Apple verification server: {Url}", _options.VerifyUrl);

var attestationBase64 = Convert.ToBase64String(attestationObject);
using var ms = new System.IO.MemoryStream();
using (var writer = new System.Text.Json.Utf8JsonWriter(ms))
{
    writer.WriteStartObject();
    writer.WriteString("teamId", _options.TeamId);
    writer.WriteString("appId", _options.AppId);
    writer.WriteString("attestation", attestationBase64);
    writer.WriteEndObject();
}
using var content = new ByteArrayContent(ms.ToArray());
content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

        var endpoint = new Uri($"{_options.VerifyUrl}/v1/attestation/verify");
        HttpResponseMessage response;
        try
        {
            response = await _httpClient.PostAsync(endpoint, content);
        }
        catch (HttpRequestException ex)
        {
            throw new VendorApiException("Apple", endpoint, 0,
                $"Network error contacting Apple verification server: {ex.Message}", ex);
        }

        if (!response.IsSuccessStatusCode)
        {
            var body = await response.Content.ReadAsStringAsync();
            throw new VendorApiException("Apple", endpoint, (int)response.StatusCode,
                $"Apple verification server rejected attestation (HTTP {(int)response.StatusCode}): {body}");
        }

        return await response.Content.ReadAsByteArrayAsync();
    }

    private static bool IsApplePlatform() =>
        OperatingSystem.IsMacOS() || OperatingSystem.IsIOS();

    private static X509Certificate2 CreatePlaceholderCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Apple-AppAttest-Placeholder", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(1));
    }
}
