namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Collections.Immutable;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Server.Services;
using Reqnroll;
using Xunit;
using AcmeAccount = Acme.Abstractions.Model.Account;
using AcmeIdentifier = Acme.Abstractions.Model.Identifier;
using AcmeOrder = Acme.Abstractions.Model.Order;
using ChallengeTypes = OpenCertServer.Acme.Abstractions.Model.ChallengeTypes;

/// <summary>
/// Step definitions for device-attest-core.feature.
/// Tests that DeviceAttest01 is included in AllTypes and that the authorization
/// factory creates device-attest-01 challenges for new orders.
/// </summary>
[Binding]
public sealed class DeviceAttestCoreSteps
{
    private ImmutableArray<string> _allTypes;
    private AcmeOrder? _order;
    private AcmeAccount? _account;

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

    // ─── Scenario 2: Authorization includes device-attest-01 challenge ────────

    [Given(@"an ACME client has registered with the server and created a new order")]
    public void GivenAnAcmeClientHasRegisteredAndCreatedANewOrder()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var securityKey = new RsaSecurityKey(rsa.ExportParameters(true));
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
        _account = new AcmeAccount(jwk, null, DateTimeOffset.UtcNow) { Status = AccountStatus.Valid };
        _order = new AcmeOrder(_account, [new AcmeIdentifier("dns", "device.example.com")], null)
        {
            Expires = DateTimeOffset.UtcNow.AddDays(1)
        };
    }

    [When(@"the order is authorized for certificate issuance")]
    public void WhenTheOrderIsAuthorizedForCertificateIssuance()
    {
        Assert.NotNull(_order);
        var factory = new DefaultAuthorizationFactory();
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
}
