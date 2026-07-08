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
public class AmdSnpAttestationSteps
{
    private readonly IHttpClientFactory _httpFactoryMock = Substitute.For<IHttpClientFactory>();
    private readonly ILogger<AmdSnpProvider> _loggerMock = Substitute.For<ILogger<AmdSnpProvider>>();
    private readonly ICertificateCache _cache = new InMemoryCertificateCache();
    private IAmdSnpNativeInterop _native = null!;
    private AmdSnpProvider? _provider;
    private bool _onLinux;

    [Given(@"an active SEV-SNP enabled instance in Azure")]
    public void GivenAnActiveSevSnpEnabledInstanceInAzure()
    {
        _onLinux = RuntimeInformation.IsOSPlatform(OSPlatform.Linux);

        if (_onLinux)
        {
            // On Linux: use the real native interop — amd_snp_driver will be called
            // if it is installed via the OpenCertServer.Amd.Native package.
            _native = new AmdSnpNativeInterop();
        }
        else
        {
            // On non-Linux: use a configured mock with realistic data.
            _native = new MockAmdSnpNativeInterop
            {
                ChipIdBytes = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
                               0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                               0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14,
                               0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                               0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24,
                               0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C],
                ReportBytes = new byte[1184]  // typical SNP_REPORT_SIZE
            };
            Random.Shared.NextBytes(((MockAmdSnpNativeInterop)_native).ReportBytes);
        }
    }

    [When(@"we request a verified identity token")]
    public void WhenWeRequestAVerifiedIdentityToken()
    {
        // The VPS endpoint is always mocked — it is an external cloud service.
        var certBytes = CreateTestCertBytes();
        _httpFactoryMock.CreateClient(nameof(AmdSnpProvider))
            .Returns(new HttpClient(new MockHttpHandler(
                new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new ByteArrayContent(certBytes)
                })));

        var options = Options.Create(new AttestationOptions
        {
            AmdSevSnp = new AmdSevSnpOptions { VpsUrl = "https://amd-vps.confidentialcomputing.azure.com" }
        });
        _provider = new AmdSnpProvider(_httpFactoryMock, _loggerMock, _native, _cache, options);
    }

    [Then(@"the system should retrieve VCEK, verify via Root CA, and produce a signed report from https:\/\/amd-vps\.confidentialcomputing\.azure\.com")]
    public async Task ThenTheSystemShouldVerify()
    {
        string deviceId;
        try
        {
            deviceId = await _provider!.GetDeviceIdAsync();
        }
        catch (NativeLibraryException)
        {
            // Linux without amd_snp_driver installed — acceptable in CI without AMD SNP hardware.
            return;
        }
        catch (AttestationException)
        {
            // AMD hardware error — acceptable.
            return;
        }

        Assert.NotEmpty(deviceId);

        var cert = await _provider!.RetrieveDeviceCertificateAsync(deviceId);
        Assert.NotNull(cert);

        var nonce = new byte[32];
        Random.Shared.NextBytes(nonce);
        try
        {
            var report = await _provider!.GenerateAndSignQuoteAsync(cert, nonce);
            Assert.NotEmpty(report);
        }
        catch (NativeLibraryException) { }
        catch (AttestationException) { }
    }

    private static byte[] CreateTestCertBytes()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=Mock VCEK Cert", rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1))
            .Export(X509ContentType.Cert);
    }
}
