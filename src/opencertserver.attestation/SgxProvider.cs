using System;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using OpenCertServer.Attestation.Native;

namespace OpenCertServer.Attestation;

/// <summary>
/// Implementation of Intel SGX Attestation using DCAP and Azure/AWS PCCS endpoints.
/// </summary>
public class SgxProvider : IAttestationProvider
{
    public string VendorName => "Intel";
    private readonly HttpClient _httpClient;
    private readonly ILogger<SgxProvider> _logger;
    private readonly string _pccsUrl;

    public SgxProvider(IHttpClientFactory httpClientFactory, ILogger<SgxProvider> logger, IConfiguration config)
    {
        _httpClient = httpClientFactory.CreateClient("SgxProvider");
        _logger = logger;
        // Config mapping per spec section 6.1
        _pccsUrl = config["Providers:IntelSgx:PccsUrl"] ?? throw new InvalidOperationException("PCCS URL not configured.");
    }

    public async Task<string> GetDeviceIdAsync()
    {
        uint size = 0;
        uint tcb = 0;
        // Calling native libsgx_dcap_ql to get PCK ID
        int result = IntelSgxNative.sgx_get_pck_id(out IntPtr pckIdPtr, ref size, ref tcb);

        if (result != 0)
        {
            _logger.LogError("SGX Native Error: Failed to retrieve PCK ID. Code: {Result}", result);
            throw new Exception($"Native SGX error {result}");
        }

        // Convert the native pointer to a hex string for REST API usage as per spec 4.2
        return ConvertPointerToHexString(pckIdPtr, (int)size);
    }

    public async Task<X509Certificate2> RetrieveDeviceCertificateAsync(string deviceId)
    {
        _logger.LogInformation("Fetching PCK certificate from PCCS: {Url}/{DeviceId}", _pccsUrl, deviceId);
        
        // REST request per spec 4.2 (Binary hardware ID to Hex strings for URI endpoints)
        var response = await _httpClient.GetAsync($"{_pccsUrl}/certs/{deviceId}");
        response.EnsureSuccessStatusCode();

        var certBytes = await response.Content.ReadAsByteArrayAsync();
        // Use X509CertificateLoader as per .NET 10 standards (SYSLIB0057)
        return X509CertificateLoader.LoadCertificate(certBytes);
    }

    public async Task<byte[]> GenerateAndSignQuoteAsync(X509Certificate2 cert, byte[] nonce)
    {
        _logger.LogInformation("Generating SGX Quote using native primitives.");
        uint quoteSize = 0;
        // Use ReadOnlySpan for nonce as per spec 4.1 & 8.2
        int result = IntelSgxNative.sgx_create_quote(IntPtr.Zero, ref quoteSize, nonce);

        if (result != 0)
        {
            throw new Exception($"SGX Quote generation failed with code {result}");
        }

        byte[] quote = new byte[quoteSize];
        unsafe
        {
            fixed (byte* pQuote = quote)
            {
                int finalResult = IntelSgxNative.sgx_create_quote((IntPtr)pQuote, ref quoteSize, nonce);
                if (finalResult != 0) throw new Exception($"SGX Quote signing failed: {finalResult}");
            }
        }

        return quote;
    }

    private string ConvertPointerToHexString(IntPtr ptr, int length)
    {
        byte[] buffer = new byte[length];
        unsafe
        {
            byte* pSrc = (byte*)ptr.ToPointer();
            for (int i = 0; i < length; i++)
            {
                buffer[i] = pSrc[i];
            }
        }
        return BitConverter.ToString(buffer).Replace("-", "");
    }
}
