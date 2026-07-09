using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenCertServer.Attestation.Native;

namespace OpenCertServer.Attestation;

/// <summary>
/// AMD SEV-SNP attestation provider using VCEK retrieval and VPS interaction.
/// </summary>
public sealed class AmdSnpProvider : IAttestationProvider
{
    public string VendorName => "AMD";

    private readonly HttpClient _httpClient;
    private readonly ILogger<AmdSnpProvider> _logger;
    private readonly IAmdSnpNativeInterop _native;
    private readonly ICertificateCache _cache;
    private readonly AmdSevSnpOptions _options;

    public AmdSnpProvider(
        IHttpClientFactory httpClientFactory,
        ILogger<AmdSnpProvider> logger,
        IAmdSnpNativeInterop native,
        ICertificateCache cache,
        IOptions<AttestationOptions> options)
    {
        _httpClient = httpClientFactory.CreateClient(nameof(AmdSnpProvider));
        _logger = logger;
        _native = native;
        _cache = cache;
        _options = options.Value.AmdSevSnp;
    }

    public Task<string> GetDeviceIdAsync()
    {
        uint size = 0;
        int result = _native.GetVcekChipId(out IntPtr chipIdPtr, ref size);

        if (result != AmdSnpErrorCodes.Success)
        {
            var name = AmdSnpErrorCodes.GetName(result);
            _logger.LogError("AMD SNP native error retrieving VCEK ChipID: {Name} ({Code})", name, result);
            throw new AttestationException(
                $"Failed to retrieve AMD VCEK ChipID: {name}",
                errorCode: result,
                vendorErrorName: name);
        }

        var hex = PointerToHex(chipIdPtr, (int)size);
        return Task.FromResult(hex);
    }

    public async Task<X509Certificate2> RetrieveDeviceCertificateAsync(string deviceId)
    {
        var cached = _cache.Get(deviceId);
        if (cached is not null)
        {
            _logger.LogDebug("AMD SNP certificate cache hit for device {DeviceId}", deviceId);
            return cached;
        }

        _logger.LogInformation("Fetching VCEK certificate from VPS: {Url}/certs/{DeviceId}", _options.VpsUrl, deviceId);
        var endpoint = new Uri($"{_options.VpsUrl}/certs/{deviceId}");
        HttpResponseMessage response;
        try
        {
            response = await _httpClient.GetAsync(endpoint);
        }
        catch (HttpRequestException ex)
        {
            throw new VendorApiException("AMD", endpoint, 0,
                $"Network error contacting VPS at {endpoint}: {ex.Message}", ex);
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new VendorApiException("AMD", endpoint, (int)response.StatusCode,
                $"VPS returned HTTP {(int)response.StatusCode} for device {deviceId}");
        }

        var certBytes = await response.Content.ReadAsByteArrayAsync();
        var cert = X509CertificateLoader.LoadCertificate(certBytes);
        _cache.Set(deviceId, cert, _options.CertificateCacheTtl);
        return cert;
    }

    public unsafe Task<byte[]> GenerateAndSignQuoteAsync(X509Certificate2 cert, byte[] nonce)
    {
        _logger.LogInformation("Generating AMD SNP attestation report.");
        uint reportSize = 0;
        int result = _native.GenerateReport(IntPtr.Zero, ref reportSize, nonce.AsSpan());

        if (result != AmdSnpErrorCodes.Success)
        {
            var name = AmdSnpErrorCodes.GetName(result);
            throw new AttestationException($"AMD SNP report size query failed: {name}", result, name);
        }

        byte[] report = new byte[reportSize];
        fixed (byte* pReport = report)
        {
            int finalResult = _native.GenerateReport((IntPtr)pReport, ref reportSize, nonce.AsSpan());
            if (finalResult != AmdSnpErrorCodes.Success)
            {
                var name = AmdSnpErrorCodes.GetName(finalResult);
                throw new AttestationException($"AMD SNP report signing failed: {name}", finalResult, name);
            }
        }

        return Task.FromResult(report);
    }

    private static string PointerToHex(IntPtr ptr, int length)
    {
        if (length <= 0) return string.Empty;
        var buffer = new byte[length];
        unsafe
        {
            new ReadOnlySpan<byte>((byte*)ptr.ToPointer(), length).CopyTo(buffer);
        }
        return Convert.ToHexString(buffer);
    }
}
