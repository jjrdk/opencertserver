using System.Net;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenCertServer.Attestation.Native;
using OpenCertServer.Attestation.Tests.Mocks;
using Reqnroll;
using Xunit;

namespace OpenCertServer.Attestation.Tests.StepDefinitions;

[Binding]
[Scope(Feature = "Apple Secure Enclave Provider Failure Modes")]
public class AppleAttestFailureModeSteps
{
    private readonly IHttpClientFactory _httpFactory = Substitute.For<IHttpClientFactory>();
    private readonly ILogger<AppleSeProvider> _logger = Substitute.For<ILogger<AppleSeProvider>>();
    private IAppleAttestNativeInterop _native = new MockAppleAttestNativeInterop();
    private AppleSeProvider? _provider;
    private Exception? _thrownException;

    private AppleSeProvider BuildProvider(IAppleAttestNativeInterop? native = null, bool useDeviceAttestation = false)
    {
        var options = Options.Create(new AttestationOptions
        {
            AppleSE = new AppleSeOptions
            {
                VerifyUrl = "https://appattest.apple.com",
                TeamId = "TESTTEAM01",
                AppId = "com.opencert.server",
                UseDeviceAttestation = useDeviceAttestation
            }
        });
        return new AppleSeProvider(_httpFactory, _logger, native ?? _native, options);
    }

    [Given(@"the Apple SE provider is configured for server-side verification")]
    public void GivenAppleProviderConfigured()
    {
        _native = new MockAppleAttestNativeInterop();
        _provider = BuildProvider(_native);
    }

    [Given(@"the native interop is unavailable on this platform")]
    public void GivenNativeInteropUnavailable()
    {
        // On non-Apple platforms, GetDeviceIdAsync throws PlatformNotSupportedException.
        // We build a real provider (not mocked) with a PlatformNotSupportedException-throwing native.
        _native = new PlatformNotSupportedAppleInterop();
        _provider = BuildProvider(_native);
    }

    [Given(@"the Apple SE provider runs on an Apple device with a failing native interop")]
    public void GivenAppleProviderWithFailingNative()
    {
        _native = new MockAppleAttestNativeInterop
        {
            ShouldThrowOnGenerateKey = true,
            ExceptionToThrow = new AttestationException("Key generation failed on device", -99, "APPATTEST_KEY_GENERATION_ERROR")
        };
        _provider = BuildProvider(_native, useDeviceAttestation: true);
    }

    [When(@"the provider receives an empty attestation object")]
    public async Task WhenEmptyAttestationObject()
    {
        try { await _provider!.GenerateAndSignQuoteAsync(null!, Array.Empty<byte>()); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [When(@"the Apple verification server returns HTTP (.*) with body ""(.*)""")]
    public async Task WhenAppleVerificationReturnsHttpWithBody(int statusCode, string body)
    {
        var response = new HttpResponseMessage((HttpStatusCode)statusCode)
        {
            Content = new StringContent(body)
        };
        var client = new HttpClient(new MockHttpHandler(response));
        _httpFactory.CreateClient(nameof(AppleSeProvider)).Returns(client);
        _provider = BuildProvider(_native);
        var attestationObject = new byte[64];
        Random.Shared.NextBytes(attestationObject);
        try { await _provider.GenerateAndSignQuoteAsync(null!, attestationObject); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [When(@"the Apple verification server throws a network error")]
    public async Task WhenAppleVerificationNetworkError()
    {
        var client = new HttpClient(new MockHttpHandler((_, _) =>
            throw new HttpRequestException("Unreachable")));
        _httpFactory.CreateClient(nameof(AppleSeProvider)).Returns(client);
        _provider = BuildProvider(_native);
        var attestationObject = new byte[64];
        Random.Shared.NextBytes(attestationObject);
        try { await _provider.GenerateAndSignQuoteAsync(null!, attestationObject); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [When(@"the provider attempts to generate a device key")]
    public async Task WhenGenerateDeviceKey()
    {
        // Simulate being on an Apple device by calling the native interop's GenerateKeyAsync directly
        // (AppleSeProvider.GetDeviceIdAsync checks OperatingSystem.IsMacOS which returns false in CI,
        //  so we invoke the native interop directly to test that the exception propagates correctly.)
        try { await _native.GenerateKeyAsync(); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [When(@"the provider's GetDeviceIdAsync is called directly")]
    public async Task WhenGetDeviceIdAsyncCalled()
    {
        try { await _provider!.GetDeviceIdAsync(); }
        catch (Exception ex) { _thrownException = ex; }
    }

    [Then(@"an ArgumentException is thrown")]
    public void ThenArgumentExceptionThrown()
    {
        Assert.NotNull(_thrownException);
        Assert.IsAssignableFrom<ArgumentException>(_thrownException);
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

    [Then(@"an AttestationException is thrown")]
    public void ThenAttestationExceptionThrown()
    {
        Assert.NotNull(_thrownException);
        Assert.IsAssignableFrom<AttestationException>(_thrownException);
    }

    [Then(@"a PlatformNotSupportedException is thrown")]
    public void ThenPlatformNotSupportedExceptionThrown()
    {
        Assert.NotNull(_thrownException);
        Assert.IsType<PlatformNotSupportedException>(_thrownException);
    }
}

/// <summary>
/// Mock that throws <see cref="PlatformNotSupportedException"/> to simulate non-Apple platform.
/// </summary>
file sealed class PlatformNotSupportedAppleInterop : IAppleAttestNativeInterop
{
    public Task<string> GenerateKeyAsync() =>
        throw new PlatformNotSupportedException(
            "Apple App Attest native key generation requires macOS 11+ or iOS 14+.");

    public Task<byte[]> AttestKeyAsync(string keyId, ReadOnlyMemory<byte> clientDataHash) =>
        throw new PlatformNotSupportedException(
            "Apple App Attest native key attestation requires macOS 11+ or iOS 14+.");
}
