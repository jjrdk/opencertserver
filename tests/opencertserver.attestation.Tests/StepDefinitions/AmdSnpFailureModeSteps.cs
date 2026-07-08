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
[Scope(Feature = "AMD SEV-SNP Provider Failure Modes")]
public class AmdSnpFailureModeSteps
{
    private readonly IHttpClientFactory _httpFactory = Substitute.For<IHttpClientFactory>();
    private readonly ILogger<AmdSnpProvider> _logger = Substitute.For<ILogger<AmdSnpProvider>>();
    private Exception? _thrownException;
    private AmdSnpProvider? _provider;
    private IAmdSnpNativeInterop _native = new MockAmdSnpNativeInterop();

    private AmdSnpProvider BuildProvider(IAmdSnpNativeInterop? native = null, string vpsUrl = "https://vps.test")
    {
        var options = Options.Create(new AttestationOptions
        {
            AmdSevSnp = new AmdSevSnpOptions { VpsUrl = vpsUrl }
        });
        return new AmdSnpProvider(_httpFactory, _logger, native ?? _native, new InMemoryCertificateCache(), options);
    }

    [Given(@"the AMD SNP native driver is not installed")]
    public void GivenAmdDriverNotInstalled()
    {
        _native = new MissingAmdSnpNativeInterop();
        _provider = BuildProvider(_native);
    }

    [Given(@"the AMD SNP native driver returns error code for permission denied")]
    public void GivenAmdPermissionDenied()
    {
        _native = new MockAmdSnpNativeInterop { GetVcekChipIdReturnCode = AmdSnpErrorCodes.PermissionDenied };
        _provider = BuildProvider(_native);
    }

    [Given(@"the AMD SNP native driver returns error code for hardware not supported")]
    public void GivenAmdNotSupported()
    {
        _native = new MockAmdSnpNativeInterop
        {
            GetVcekChipIdReturnCode = AmdSnpErrorCodes.Success,
            GenerateReportReturnCode = AmdSnpErrorCodes.NotSupported
        };
        _provider = BuildProvider(_native);
    }

    [Given(@"a configured AMD provider with a valid ChipID")]
    public void GivenConfiguredAmdProvider()
    {
        _native = new MockAmdSnpNativeInterop();
        _provider = BuildProvider(_native);
    }

    [When(@"the provider attempts to retrieve the VCEK ChipID")]
    public async Task WhenRetrieveVcekChipId()
    {
        try { await _provider!.GetDeviceIdAsync(); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [When(@"the VPS endpoint returns HTTP (.*)")]
    public async Task WhenVpsReturnsHttpStatus(int statusCode)
    {
        var response = new HttpResponseMessage((HttpStatusCode)statusCode);
        var client = new HttpClient(new MockHttpHandler(response));
        _httpFactory.CreateClient(nameof(AmdSnpProvider)).Returns(client);
        _provider = BuildProvider(_native);
        try { await _provider.RetrieveDeviceCertificateAsync("DEADBEEF"); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [When(@"the VPS endpoint throws a network error")]
    public async Task WhenVpsThrowsNetworkError()
    {
        var client = new HttpClient(new MockHttpHandler((_, _) =>
            throw new HttpRequestException("Connection refused")));
        _httpFactory.CreateClient(nameof(AmdSnpProvider)).Returns(client);
        _provider = BuildProvider(_native);
        try { await _provider.RetrieveDeviceCertificateAsync("DEADBEEF"); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [When(@"the provider attempts to generate an attestation report")]
    public async Task WhenGenerateReport()
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
}
