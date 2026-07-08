using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OpenCertServer.Attestation.Native;

namespace OpenCertServer.Attestation;

/// <summary>
/// Intel SGX attestation provider using DCAP and Azure/AWS PCCS endpoints.
/// </summary>
public sealed class SgxProvider : IAttestationProvider
{
    public string VendorName => "Intel";

    private readonly HttpClient _httpClient;
    private readonly ILogger<SgxProvider> _logger;
    private readonly ISgxNativeInterop _native;
    private readonly ICertificateCache _cache;
    private readonly IntelSgxOptions _options;

    public SgxProvider(
        IHttpClientFactory httpClientFactory,
        ILogger<SgxProvider> logger,
        ISgxNativeInterop native,
        ICertificateCache cache,
        IOptions<AttestationOptions> options)
    {
        _httpClient = httpClientFactory.CreateClient(nameof(SgxProvider));
        _logger = logger;
        _native = native;
        _cache = cache;
        _options = options.Value.IntelSgx;
    }

    public Task<string> GetDeviceIdAsync()
    {
        uint size = 0;
        uint tcb = 0;
        int result = _native.GetPckId(out IntPtr pckIdPtr, ref size, ref tcb);

        if (result != SgxErrorCodes.Success)
        {
            var name = SgxErrorCodes.GetName(result);
            _logger.LogError("SGX native error retrieving PCK ID: {Name} (0x{Code:X8})", name, result);
            throw new AttestationException(
                $"Failed to retrieve SGX PCK ID: {name}",
                errorCode: result,
                vendorErrorName: name);
        }

        return Task.FromResult(PointerToHex(pckIdPtr, (int)size));
    }

    public async Task<X509Certificate2> RetrieveDeviceCertificateAsync(string deviceId)
    {
        var cached = _cache.Get(deviceId);
        if (cached is not null)
        {
            _logger.LogDebug("SGX certificate cache hit for device {DeviceId}", deviceId);
            return cached;
        }

        _logger.LogInformation("Fetching PCK certificate from PCCS: {Url}/certs/{DeviceId}", _options.PccsUrl, deviceId);
        var endpoint = new Uri($"{_options.PccsUrl}/certs/{deviceId}");
        HttpResponseMessage response;
        try
        {
            response = await _httpClient.GetAsync(endpoint);
        }
        catch (HttpRequestException ex)
        {
            throw new VendorApiException("Intel", endpoint, 0,
                $"Network error contacting PCCS at {endpoint}: {ex.Message}", ex);
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new VendorApiException("Intel", endpoint, (int)response.StatusCode,
                $"PCCS returned HTTP {(int)response.StatusCode} for device {deviceId}");
        }

        var certBytes = await response.Content.ReadAsByteArrayAsync();
        var cert = X509CertificateLoader.LoadCertificate(certBytes);
        _cache.Set(deviceId, cert, _options.CertificateCacheTtl);
        return cert;
    }

    public unsafe Task<byte[]> GenerateAndSignQuoteAsync(X509Certificate2 cert, byte[] nonce)
    {
        _logger.LogInformation("Generating SGX DCAP quote.");
        uint quoteSize = 0;
        int result = _native.CreateQuote(IntPtr.Zero, ref quoteSize, nonce.AsSpan());

        if (result != SgxErrorCodes.Success)
        {
            var name = SgxErrorCodes.GetName(result);
            throw new AttestationException($"SGX quote size query failed: {name}", result, name);
        }

        byte[] quote = new byte[quoteSize];
        fixed (byte* pQuote = quote)
        {
            int finalResult = _native.CreateQuote((IntPtr)pQuote, ref quoteSize, nonce.AsSpan());
            if (finalResult != SgxErrorCodes.Success)
            {
                var name = SgxErrorCodes.GetName(finalResult);
                throw new AttestationException($"SGX quote signing failed: {name}", finalResult, name);
            }
        }

        return Task.FromResult(quote);
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
