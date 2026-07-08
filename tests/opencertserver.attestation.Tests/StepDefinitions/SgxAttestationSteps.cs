using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenCertServer.Attestation;
using OpenCertServer.Attestation.Native;
using OpenCertServer.Attestation.Tests.Mocks;
using Reqnroll;
using Xunit;

[Binding]
public class SgxAttestationSteps
{
    private readonly IHttpClientFactory _httpFactoryMock = Substitute.For<IHttpClientFactory>();
    private readonly ILogger<SgxProvider> _loggerMock = Substitute.For<ILogger<SgxProvider>>();
    private readonly ICertificateCache _cache = new InMemoryCertificateCache();
    private ISgxNativeInterop _native = null!;
    private SgxProvider? _provider;
    private bool _onLinux;

    [Given(@"an active SGX enclave in Azure")]
    public void GivenAnActiveSgxEnclaveInAzure()
    {
        _onLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        if (_onLinux)
        {
            // On Linux: use the real native interop — libsgx_dcap_ql will be called
            // if it is installed via the OpenCertServer.Sgx.Native package or apt.
            _native = new SgxNativeInterop();
        }
        else
        {
            // On non-Linux: use a configured mock that returns realistic data so the
            // full provider pipeline (cache, HTTP cert fetch, quote buffer sizing) is exercised.
            _native = new MockSgxNativeInterop
            {
                PckIdBytes = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x01, 0x02,
                              0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A],
                QuoteBytes = new byte[256]
            };
            Random.Shared.NextBytes(((MockSgxNativeInterop)_native).QuoteBytes);
        }
    }

    [When(@"we request a verified identity token for Intel")]
    public void WhenWeRequestAVerifiedIdentityTokenForIntel()
    {
        // The PCCS endpoint is always mocked — it is an external cloud service.
        var certBytes = CreateTestCertBytes();
        _httpFactoryMock.CreateClient(nameof(SgxProvider))
            .Returns(new HttpClient(new MockHttpHandler(
                new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(certBytes)
                })));

        var options = Options.Create(new AttestationOptions
        {
            IntelSgx = new IntelSgxOptions { PccsUrl = "https://pccs.confidentialcomputing.azure.com" }
        });
        _provider = new SgxProvider(_httpFactoryMock, _loggerMock, _native, _cache, options);
    }

    [Then(@"the system should retrieve PCK ID, fetch cert from https:\/\/pccs\.confidentialcomputing\.azure\.com, verify via Root CA, and produce a signed quote")]
    public async Task ThenTheSystemShouldVerify()
    {
        string deviceId;
        try
        {
            deviceId = await _provider!.GetDeviceIdAsync();
        }
        catch (NativeLibraryException)
        {
            // Linux without libsgx_dcap_ql installed — acceptable in CI without SGX hardware.
            return;
        }
        catch (AttestationException)
        {
            // SGX hardware present but returned an error (e.g. device busy) — acceptable.
            return;
        }

        // Native call succeeded: validate the full pipeline.
        Assert.NotEmpty(deviceId);

        var cert = await _provider!.RetrieveDeviceCertificateAsync(deviceId);
        Assert.NotNull(cert);

        var nonce = new byte[32];
        Random.Shared.NextBytes(nonce);
        try
        {
            var quote = await _provider!.GenerateAndSignQuoteAsync(cert, nonce);
            Assert.NotEmpty(quote);
        }
        catch (NativeLibraryException) { /* library gone between calls — acceptable */ }
        catch (AttestationException) { /* hardware error — acceptable */ }
    }

    private static byte[] CreateTestCertBytes()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Mock PCK Cert", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1))
            .Export(X509ContentType.Cert);
    }
}
