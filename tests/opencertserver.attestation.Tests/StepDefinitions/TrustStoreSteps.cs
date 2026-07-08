using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using Reqnroll;

namespace OpenCertServer.Attestation.Tests.StepDefinitions;

[Binding]
[Scope(Feature = "Global Trust Root and Revocation")]
public class TrustStoreSteps
{
    private readonly ILogger<TrustStore> _loggerMock = Substitute.For<ILogger<TrustStore>>();
    private TrustStore _trustStore = null!;
    private (bool IsValid, string Error) _result;

    [Given(@"a device certificate not signed by a pinned Root CA")]
    public void GivenADeviceCertificateNotSignedByAPinnedRootCA()
    {
        var options = Options.Create(new AttestationOptions
        {
            RevocationMode = X509RevocationMode.NoCheck
        });
        _trustStore = new TrustStore(options, _loggerMock);

        // Register a self-signed root so the vendor is known; the test cert is from a DIFFERENT CA.
        var pinnedRoot = CreateSelfSignedCert("CN=Pinned Intel Root CA");
        _trustStore.RegisterTestRoot("Intel", pinnedRoot);
    }

    [When(@"running ValidateChain\(\)")]
    public void WhenRunningValidateChain()
    {
        var untrustedCert = CreateSelfSignedCert("CN=Untrusted Device Cert");
        _result = _trustStore.ValidateChain(untrustedCert, "Intel");
    }

    [Then(@"it must return false with ""Untrusted Vendor Root"" error")]
    public void ThenItMustReturnFalseWithUntrustedVendorRootError()
    {
        if (_result.IsValid || _result.Error != "Untrusted Vendor Root")
        {
            throw new Exception($"Expected failure with 'Untrusted Vendor Root', but got IsValid={_result.IsValid}, Error='{_result.Error}'");
        }
    }

    private static X509Certificate2 CreateSelfSignedCert(string dn)
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(new X500DistinguishedName(dn), rsa,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
    }
}
