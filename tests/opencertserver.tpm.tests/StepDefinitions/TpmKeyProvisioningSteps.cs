namespace OpenCertServer.Tpm.Tests.StepDefinitions;

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.Ca;
using Reqnroll;
using Xunit;

[Binding]
public sealed class TpmKeyProvisioningSteps : IDisposable
{
    private readonly ScenarioContext _scenarioContext;
    private ITpmKeyProvider? _provider;
    private byte[]? _signature;
    private byte[]? _signedData;
    private CaProfile? _profile;
    private TpmCaProfileFactory? _factory;

    public TpmKeyProvisioningSteps(ScenarioContext scenarioContext)
        => _scenarioContext = scenarioContext;

    // -----------------------------------------------------------------
    // Givens
    // -----------------------------------------------------------------

    [Given("an RSA key is provisioned at handle 0x81010001")]
    public void GivenRsaKeyIsProvisioned()
    {
        EnsureProvider();
        _provider!.EnsureRsaKey(0x81010001);
    }

    [Given("an ECDsa key is provisioned at handle 0x81010002")]
    public void GivenEcDsaKeyIsProvisioned()
    {
        EnsureProvider();
        _provider!.EnsureEcDsaKey(0x81010002);
    }

    [Given("an RSA CA profile named \"default\" has been created")]
    public void GivenRsaProfileExists()
    {
        // Use the shared provider so that the rollover When-step can reuse the same
        // TCP connection — the IBM TPM2 simulator only handles one connection at a time.
        EnsureProvider();
        _factory = new TpmCaProfileFactory(GetContainerOptions(), _provider!, ownsKeyProvider: false);
        _profile = _factory.CreateOrLoadRsaProfile("default");
    }

    // -----------------------------------------------------------------
    // Whens
    // -----------------------------------------------------------------

    [When("I provision an RSA key at handle 0x81010001")]
    [When("I provision an RSA key at handle 0x81010001 again")]
    public void WhenIProvisionRsaKey()
    {
        EnsureProvider();
        _provider!.EnsureRsaKey(0x81010001);
    }

    [When("I provision an ECDsa key at handle 0x81010002")]
    [When("I provision an ECDsa key at handle 0x81010002 again")]
    public void WhenIProvisionEcDsaKey()
    {
        EnsureProvider();
        _provider!.EnsureEcDsaKey(0x81010002);
    }

    [When("I sign \"(.*)\" with the RSA key at handle 0x81010001")]
    public void WhenISignWithRsa(string message)
    {
        EnsureProvider();
        _signedData = System.Text.Encoding.UTF8.GetBytes(message);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(_signedData);
        _signature = _provider!.SignRsa(0x81010001, hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
    }

    [When("I sign \"(.*)\" with the ECDsa key at handle 0x81010002")]
    public void WhenISignWithEcDsa(string message)
    {
        EnsureProvider();
        _signedData = System.Text.Encoding.UTF8.GetBytes(message);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(_signedData);
        _signature = _provider!.SignEcDsa(0x81010002, hash, HashAlgorithmName.SHA256);
    }

    [When("I create an RSA CA profile named \"(.*)\" via TpmCaProfileFactory")]
    public void WhenICreateRsaProfile(string profileName)
    {
        _factory = new TpmCaProfileFactory(GetContainerOptions());
        _profile = _factory.CreateOrLoadRsaProfile(profileName);
    }

    [When("I create an ECDsa CA profile named \"(.*)\" via TpmCaProfileFactory")]
    public void WhenICreateEcDsaProfile(string profileName)
    {
        _factory = new TpmCaProfileFactory(GetContainerOptions());
        _profile = _factory.CreateOrLoadEcDsaProfile(profileName);
    }

    [When("I roll over to a new RSA CA certificate")]
    public void WhenIRollOver()
    {
        Assert.NotNull(_profile);
        Assert.NotNull(_factory);

        // Use handle 0x81010003 so the new key doesn't collide with the existing one.
        var opts = GetContainerOptions(rsaKeyHandle: 0x81010003);

        // Share the same TssTpmKeyProvider connection (_provider) with factory2.
        // The IBM TPM2 simulator only handles ONE TCP connection at a time; opening a
        // second connection while _factory is alive would deadlock.
        // _provider was set by GivenRsaProfileExists via EnsureProvider(); ownsKeyProvider:false
        // prevents factory2 from closing the shared connection on disposal.
        using var factory2 = new TpmCaProfileFactory(opts, _provider!, ownsKeyProvider: false);
        var newProfile = factory2.CreateOrLoadRsaProfile("default-new");

        _profile.RollOver(newProfile.CertificateChain[0], newProfile.PrivateKey);
        newProfile.Dispose();
    }

    // -----------------------------------------------------------------
    // Thens
    // -----------------------------------------------------------------

    [Then("the RSA key should exist at handle 0x81010001")]
    public void ThenRsaKeyExists()
    {
        var pub = _provider!.ExportRsaPublicParameters(0x81010001);
        Assert.NotNull(pub.Modulus);
        Assert.True(pub.Modulus!.Length >= 256); // 2048-bit key
    }

    [Then("only one key should exist at handle 0x81010001")]
    public void ThenOnlyOneRsaKey()
    {
        var pub = _provider!.ExportRsaPublicParameters(0x81010001);
        Assert.NotNull(pub.Modulus);
    }

    [Then("the ECDsa key should exist at handle 0x81010002")]
    public void ThenEcDsaKeyExists()
    {
        var pub = _provider!.ExportEcDsaPublicParameters(0x81010002);
        Assert.NotNull(pub.Q.X);
        Assert.Equal(32, pub.Q.X!.Length);
    }

    [Then("only one key should exist at handle 0x81010002")]
    public void ThenOnlyOneEcDsaKey()
    {
        var pub = _provider!.ExportEcDsaPublicParameters(0x81010002);
        Assert.NotNull(pub.Q.X);
    }

    [Then("the signature should verify against the RSA public key at handle 0x81010001")]
    public void ThenRsaSignatureVerifies()
    {
        Assert.NotNull(_signature);
        Assert.NotNull(_signedData);
        var pub = _provider!.ExportRsaPublicParameters(0x81010001);
        using var rsa = RSA.Create();
        rsa.ImportParameters(pub);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(_signedData!);
        Assert.True(rsa.VerifyHash(hash, _signature!, HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    }

    [Then("the signature should verify against the ECDsa public key at handle 0x81010002")]
    public void ThenEcDsaSignatureVerifies()
    {
        Assert.NotNull(_signature);
        Assert.NotNull(_signedData);
        var pub = _provider!.ExportEcDsaPublicParameters(0x81010002);
        using var ecdsa = ECDsa.Create(pub);
        using var sha = SHA256.Create();
        var hash = sha.ComputeHash(_signedData!);
        Assert.True(ecdsa.VerifyHash(hash, _signature!));
    }

    [Then("the profile certificate should be a CA certificate")]
    public void ThenProfileCertIsCa()
    {
        Assert.NotNull(_profile);
        var cert = _profile!.CertificateChain[0];
        var bc = cert.Extensions.OfType<X509BasicConstraintsExtension>().Single();
        Assert.True(bc.CertificateAuthority);
    }

    [Then("the profile private key should be a TpmRsa instance")]
    public void ThenPrivateKeyIsTpmRsa()
    {
        Assert.NotNull(_profile);
        Assert.IsType<TpmRsa>(_profile!.PrivateKey);
    }

    [Then("the profile private key should be a TpmEcDsa instance")]
    public void ThenPrivateKeyIsTpmEcDsa()
    {
        Assert.NotNull(_profile);
        Assert.IsType<TpmEcDsa>(_profile!.PrivateKey);
    }

    [Then("the published chain should contain (\\d+) certificates")]
    public void ThenPublishedChainCount(int count)
    {
        Assert.NotNull(_profile);
        Assert.Equal(count, _profile!.PublishedCertificateChain.Count);
    }

    [Then("the published chain should contain the new active certificate")]
    public void ThenPublishedChainHasNewActive()
    {
        Assert.NotNull(_profile);
        var activePrint = _profile!.CertificateChain[0].Thumbprint;
        Assert.Contains(_profile.PublishedCertificateChain.Cast<X509Certificate2>(),
            c => string.Equals(c.Thumbprint, activePrint, StringComparison.OrdinalIgnoreCase));
    }

    [Then("the published chain should contain the old certificate \\(OldWithOld\\)")]
    public void ThenPublishedChainHasOldWithOld()
    {
        Assert.NotNull(_profile);
        // After rollover there must be at least 2 distinct subjects in the published chain.
        var subjects = _profile!.PublishedCertificateChain
            .Cast<X509Certificate2>()
            .Select(c => c.Subject)
            .Distinct()
            .ToList();
        Assert.True(subjects.Count >= 2, "Expected at least two distinct subjects (old and new) in the published chain.");
    }

    // -----------------------------------------------------------------
    // IDisposable — clean up objects created during the test
    // -----------------------------------------------------------------

    public void Dispose()
    {
        _profile?.Dispose();
        _factory?.Dispose();
        _provider?.Dispose();
    }

    // -----------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------

    private void EnsureProvider()
    {
        if (_provider != null) return;
        _provider = new TssTpmKeyProvider(GetContainerOptions());
    }

    private TpmCaOptions GetContainerOptions(
        uint rsaKeyHandle = 0x81010001,
        uint ecDsaKeyHandle = 0x81010002)
    {
        var container = _scenarioContext.Get<TpmSimulatorContainer>();
        return container.CreateOptions(rsaKeyHandle, ecDsaKeyHandle);
    }
}
