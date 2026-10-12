namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using Acme.Server.Services;
using Reqnroll;
using Xunit;
using AcmeAccount = Acme.Abstractions.Model.Account;
using AcmeOrder = Acme.Abstractions.Model.Order;

/// <summary>
/// Step definitions for device-attest-core.feature.
/// Tests that DeviceAttest01 is included in AllTypes and that the authorization
/// factory creates device-attest-01 challenges only when trust roots are configured.
/// </summary>
[Binding]
public sealed class DeviceAttestCoreSteps
{
    private ImmutableArray<string> _allTypes;
    private AcmeOrder? _order;
    private AcmeAccount? _account;
    private X509Certificate2Collection _trustRoots = [];

    // ─── Scenario 1: AllTypes contains device-attest-01 ──────────────────────

    [When(@"I enumerate the supported challenge types via ChallengeTypes\.AllTypes")]
    public void WhenIEnumerateSupportedChallengeTypes()
    {
        _allTypes = ChallengeTypes.AllTypes;
    }

    [Then("""
          the collection must contain "(.*)"
          """)]
    public void ThenTheCollectionMustContain(string expectedType)
    {
        Assert.Contains(expectedType, _allTypes);
    }

    // ─── Scenario 2 & 3: Authorization includes/excludes device-attest-01 ────

    [Given(@"an ACME client has registered with the server and created a new order")]
    public void GivenAnAcmeClientHasRegisteredAndCreatedANewOrder()
    {
        using var rsa = RSA.Create(2048);
        var securityKey = new RsaSecurityKey(rsa.ExportParameters(true));
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
        _account = new AcmeAccount(jwk, null, DateTimeOffset.UtcNow) { Status = AccountStatus.Valid };
        _order = new AcmeOrder(_account, [new Identifier { Type = IdentifierType.Dns, Value = "device.example.com" }],
            null)
        {
            Expires = DateTimeOffset.UtcNow.AddDays(1)
        };
    }

    [Given(@"the authorization factory is configured with a non-empty attestation trust provider")]
    public void GivenFactoryWithNonEmptyTrustProvider()
    {
        using var caKey = RSA.Create(2048);
        var caReq = new CertificateRequest("CN=Test Manufacturer CA", caKey,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        caReq.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(certificateAuthority: true, false, 0, true));
        var caCert = caReq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(10));
        _trustRoots = [caCert];
    }

    [Given(@"the authorization factory is configured with an empty attestation trust provider")]
    public void GivenFactoryWithEmptyTrustProvider()
    {
        _trustRoots = [];
    }

    [When(@"the order is authorized for certificate issuance")]
    public void WhenTheOrderIsAuthorizedForCertificateIssuance()
    {
        Assert.NotNull(_order);
        var trustProvider = new StaticAttestationTrustProvider(_trustRoots);
        var factory = new DefaultAuthorizationFactory(trustProvider);
        factory.CreateAuthorizations(_order);
    }

    [Then("""
          the authorization must include at least one challenge of type "(.*)"
          """)]
    public void ThenTheAuthorizationMustIncludeAChallengeOfType(string expectedType)
    {
        Assert.NotNull(_order);
        var challenges = _order.Authorizations
            .SelectMany(a => a.Challenges)
            .ToList();
        Assert.Contains(challenges, c => c.Type == expectedType);
    }

    [Then("""
          the authorization must not include any challenge of type "(.*)"
          """)]
    public void ThenTheAuthorizationMustNotIncludeAChallengeOfType(string expectedType)
    {
        Assert.NotNull(_order);
        var challenges = _order.Authorizations
            .SelectMany(a => a.Challenges)
            .ToList();
        Assert.DoesNotContain(challenges, c => c.Type == expectedType);
    }
}
