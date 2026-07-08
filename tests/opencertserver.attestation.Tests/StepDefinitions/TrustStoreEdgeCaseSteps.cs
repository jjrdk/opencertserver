using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using NSubstitute;
using OpenCertServer.Attestation;
using OpenCertServer.Attestation.Tests.Mocks;
using Reqnroll;
using Xunit;

namespace OpenCertServer.Attestation.Tests.StepDefinitions;

[Binding]
[Scope(Feature = "TrustStore Edge Cases")]
public class TrustStoreEdgeCaseSteps
{
    private readonly ILogger<TrustStore> _logger = Substitute.For<ILogger<TrustStore>>();
    private TrustStore _trustStore = null!;
    private (bool IsValid, string Error) _result;
    private IReadOnlyCollection<string>? _pinnedVendors;

    // CA key held in field to sign the leaf cert in a later step
    private RSA? _caKey;
    private X509Certificate2? _caCert;

    private TrustStore BuildEmptyTrustStore()
    {
        var options = Options.Create(new AttestationOptions
        {
            RevocationMode = X509RevocationMode.NoCheck  // test certs have no CRL/OCSP URLs
        });
        return new TrustStore(options, _logger);
    }

    [Given(@"the TrustStore has a pinned root CA for ""(.*)""")]
    public void GivenTrustStoreHasPinnedRoot(string vendor)
    {
        if (_trustStore is null)
            _trustStore = BuildEmptyTrustStore();

        _caKey = RSA.Create(2048);
        var req = new CertificateRequest(
            new X500DistinguishedName($"CN={vendor} Test Root CA"),
            _caKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        _caCert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        _trustStore.RegisterTestRoot(vendor, _caCert);
    }

    [Given(@"a pinned root CA for ""(.*)""")]
    public void GivenAdditionalPinnedRoot(string vendor)
    {
        GivenTrustStoreHasPinnedRoot(vendor);
    }

    [Given(@"a device certificate signed by that pinned root CA")]
    public void GivenDeviceCertSignedByPinnedRoot()
    {
        // The leaf cert will be created and validated in the When step; nothing to do here.
    }

    [When(@"ValidateChain is called with vendor ""(.*)""")]
    public void WhenValidateChainWithVendor(string vendor)
    {
        // Create a leaf cert signed by the CA that was pinned in the Given step.
        using var leafKey = RSA.Create(2048);
        var leafReq = new CertificateRequest(
            new X500DistinguishedName("CN=Device Cert"),
            leafKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        leafReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var leafCert = leafReq.Create(_caCert!, DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(1), [0x01]);
        _result = _trustStore.ValidateChain(leafCert, vendor);
    }

    [When(@"a self-signed certificate from a different CA is validated for vendor ""(.*)""")]
    public void WhenSelfSignedFromDifferentCa(string vendor)
    {
        var untrusted = TestCertificateFactory.CreateSelfSignedCert("CN=Untrusted");
        _result = _trustStore.ValidateChain(untrusted, vendor);
    }

    [When(@"a certificate is validated for vendor ""(.*)""")]
    public void WhenCertValidatedForUnknownVendor(string vendor)
    {
        var cert = TestCertificateFactory.CreateSelfSignedCert("CN=SomeCert");
        _result = _trustStore.ValidateChain(cert, vendor);
    }

    [When(@"the pinned vendors are listed")]
    public void WhenPinnedVendorsListed()
    {
        _pinnedVendors = _trustStore.PinnedVendors;
    }

    [Then(@"the result should be valid")]
    public void ThenResultShouldBeValid()
    {
        Assert.True(_result.IsValid, $"Expected valid but got error: {_result.Error}");
    }

    [Then(@"the chain validation should fail with ""(.*)""")]
    public void ThenChainValidationFailsWith(string expectedError)
    {
        Assert.False(_result.IsValid);
        Assert.Equal(expectedError, _result.Error);
    }

    [Then(@"the result should be invalid with error ""(.*)""")]
    public void ThenResultInvalidWithError(string expectedError)
    {
        Assert.False(_result.IsValid);
        Assert.Equal(expectedError, _result.Error);
    }

    [Then(@"the list should contain ""(.*)""")]
    public void ThenListShouldContain(string vendor)
    {
        Assert.NotNull(_pinnedVendors);
        Assert.Contains(vendor, _pinnedVendors, StringComparer.OrdinalIgnoreCase);
    }
}
