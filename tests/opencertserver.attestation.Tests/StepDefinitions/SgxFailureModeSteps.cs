using System.Net;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenCertServer.Attestation;
using OpenCertServer.Attestation.Native;
using OpenCertServer.Attestation.Tests.Mocks;
using Reqnroll;
using Xunit;

namespace OpenCertServer.Attestation.Tests.StepDefinitions;

[Binding]
[Scope(Feature = "Intel SGX Provider Failure Modes")]
public class SgxFailureModeSteps
{
    private readonly IHttpClientFactory _httpFactory = Substitute.For<IHttpClientFactory>();
    private readonly ILogger<SgxProvider> _logger = Substitute.For<ILogger<SgxProvider>>();
    private Exception? _thrownException;
    private SgxProvider? _provider;
    private int _httpCallCount;
    private ISgxNativeInterop _native = new MockSgxNativeInterop();

    private SgxProvider BuildProvider(ISgxNativeInterop? native = null, string pccsUrl = "https://pccs.test")
    {
        var options = Options.Create(new AttestationOptions
        {
            IntelSgx = new IntelSgxOptions { PccsUrl = pccsUrl }
        });
        return new SgxProvider(_httpFactory, _logger, native ?? _native, new InMemoryCertificateCache(), options);
    }

    [Given(@"the SGX native library is not installed")]
    public void GivenTheSgxNativeLibraryIsNotInstalled()
    {
        _native = new MissingSgxNativeInterop();
        _provider = BuildProvider(_native);
    }

    [Given(@"the SGX native driver returns error code for hardware busy")]
    public void GivenSgxNativeReturnsHardwareBusy()
    {
        _native = new MockSgxNativeInterop { GetPckIdReturnCode = SgxErrorCodes.DeviceBusy };
        _provider = BuildProvider(_native);
    }

    [Given(@"the SGX native driver returns error code for out of memory during quote creation")]
    public void GivenSgxNativeReturnsOutOfMemoryQuote()
    {
        var mock = new MockSgxNativeInterop
        {
            GetPckIdReturnCode = SgxErrorCodes.Success,
            CreateQuoteReturnCode = SgxErrorCodes.OutOfMemory
        };
        _native = mock;
        _provider = BuildProvider(mock);
    }

    [Given(@"a configured SGX provider with a valid PCK ID")]
    public void GivenConfiguredSgxProvider()
    {
        _native = new MockSgxNativeInterop();
        _provider = BuildProvider(_native);
    }

    [Given(@"the PCCS endpoint returns a valid certificate for device ""(.*)""")]
    public async Task GivenPccsReturnsCert(string _)
    {
        var certBytes = TestCertificateFactory.CreateSelfSignedCert("CN=Mock PCK")
            .Export(X509ContentType.Cert);
        var client = new HttpClient(new MockHttpHandler((_, _) =>
        {
            _httpCallCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(certBytes)
            });
        }));
        _httpFactory.CreateClient(nameof(SgxProvider)).Returns(client);
        // Prime the cache with a first fetch
        _provider = BuildProvider(_native);
    }

    [When(@"the provider attempts to retrieve the PCK ID")]
    public async Task WhenRetrievePckId()
    {
        try { await _provider!.GetDeviceIdAsync(); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [When(@"the PCCS endpoint returns HTTP (.*)")]
    public async Task WhenPccsReturnsHttpStatus(int statusCode)
    {
        var response = new HttpResponseMessage((HttpStatusCode)statusCode);
        var client = new HttpClient(new MockHttpHandler(response));
        _httpFactory.CreateClient(nameof(SgxProvider)).Returns(client);
        _provider = BuildProvider(_native);
        try { await _provider.RetrieveDeviceCertificateAsync("AABBCCDD"); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [When(@"the PCCS endpoint throws a network error")]
    public async Task WhenPccsThrowsNetworkError()
    {
        var client = new HttpClient(new MockHttpHandler((_, _) =>
            throw new HttpRequestException("Connection refused")));
        _httpFactory.CreateClient(nameof(SgxProvider)).Returns(client);
        _provider = BuildProvider(_native);
        try { await _provider.RetrieveDeviceCertificateAsync("AABBCCDD"); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [When(@"the certificate is requested twice for device ""(.*)""")]
    public async Task WhenCertRequestedTwice(string deviceId)
    {
        _httpCallCount = 0;
        var cache = new InMemoryCertificateCache();
        var options = Options.Create(new AttestationOptions
        {
            IntelSgx = new IntelSgxOptions { PccsUrl = "https://pccs.test" }
        });
        var certBytes = TestCertificateFactory.CreateSelfSignedCert("CN=Mock PCK").Export(X509ContentType.Cert);
        var client = new HttpClient(new MockHttpHandler((_, _) =>
        {
            _httpCallCount++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new ByteArrayContent(certBytes)
            });
        }));
        _httpFactory.CreateClient(nameof(SgxProvider)).Returns(client);
        var provider = new SgxProvider(_httpFactory, _logger, _native, cache, options);
        await provider.RetrieveDeviceCertificateAsync(deviceId);
        await provider.RetrieveDeviceCertificateAsync(deviceId);
    }

    [When(@"the provider attempts to generate a quote")]
    public async Task WhenGenerateQuote()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var req = new CertificateRequest("CN=Test", rsa, System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        try { await _provider!.GenerateAndSignQuoteAsync(cert, new byte[32]); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [Then(@"a NativeLibraryException is thrown with library name ""(.*)""")]
    public void ThenNativeLibraryExceptionWithName(string libraryName)
    {
        Assert.NotNull(_thrownException);
        var ex = Assert.IsType<NativeLibraryException>(_thrownException);
        Assert.Equal(libraryName, ex.LibraryName);
    }

    [Then(@"an AttestationException is thrown with vendor error name ""(.*)""")]
    public void ThenAttestationExceptionWithVendorError(string vendorErrorName)
    {
        Assert.NotNull(_thrownException);
        var ex = Assert.IsAssignableFrom<AttestationException>(_thrownException);
        Assert.Equal(vendorErrorName, ex.VendorErrorName);
    }

    [Then(@"a VendorApiException is thrown with HTTP status (.*)")]
    public void ThenVendorApiExceptionWithStatus(int status)
    {
        Assert.NotNull(_thrownException);
        var ex = Assert.IsType<VendorApiException>(_thrownException);
        Assert.Equal(status, ex.HttpStatusCode);
    }

    [Then(@"a VendorApiException is thrown for vendor ""(.*)""")]
    public void ThenVendorApiExceptionForVendor(string vendor)
    {
        Assert.NotNull(_thrownException);
        var ex = Assert.IsType<VendorApiException>(_thrownException);
        Assert.Equal(vendor, ex.Vendor);
    }

    [Then(@"the PCCS endpoint is called only once")]
    public void ThenPccsCalledOnce()
    {
        Assert.Equal(1, _httpCallCount);
    }
}
