using System.Reflection;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server.Services;
using Reqnroll;
using Xunit;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using AcmeAccount = Acme.Abstractions.Model.Account;
using AcmeChallenge = Acme.Abstractions.Model.Challenge;
using AcmeError = Acme.Abstractions.Model.AcmeError;
using AcmeIdentifier = Acme.Abstractions.Model.Identifier;
using AcmeOrder = Acme.Abstractions.Model.Order;
using AcmeAuthorization = Acme.Abstractions.Model.Authorization;

[Binding]
public sealed class DeviceAttestFactorySteps
{
    private DefaultChallengeValidatorFactory? _factory;
    private IValidateChallenges? _returnedValidator;
    private Exception? _thrownException;

    private sealed class StubHttp01 : IValidateHttp01Challenges
    {
        public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            AcmeChallenge challenge, AcmeAccount account, CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private sealed class StubDns01 : IValidateDns01Challenges
    {
        public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            AcmeChallenge challenge, AcmeAccount account, CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private sealed class StubDeviceAttest : IValidateDeviceAttestChallenges
    {
        public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            AcmeChallenge challenge, AcmeAccount account, CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private static AcmeChallenge CreateChallengeOfType(string type)
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var securityKey = new RsaSecurityKey(rsa.ExportParameters(true));
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
        var account = new AcmeAccount(jwk, null, null) { Status = AccountStatus.Valid };
        var order = new AcmeOrder(account, [new AcmeIdentifier("dns", "test.example.com")], null)
        {
            Expires = DateTimeOffset.UtcNow.AddDays(1)
        };
        var authorization = new AcmeAuthorization(order, new AcmeIdentifier("dns", "test.example.com"),
            DateTimeOffset.UtcNow.AddDays(1));
        return new AcmeChallenge(authorization, type);
    }

    private static AcmeChallenge CreateChallengeWithUnknownType()
    {
        var challenge = CreateChallengeOfType(ChallengeTypes.Http01);
        var typeBackingField = typeof(AcmeChallenge).GetField("<Type>k__BackingField",
            BindingFlags.Instance | BindingFlags.NonPublic);
        typeBackingField?.SetValue(challenge, "unknown-99");
        return challenge;
    }

    [Given(@"the challenge validator factory is initialized with all three validators")]
    public void GivenTheFactoryIsInitialized()
    {
        _factory = new DefaultChallengeValidatorFactory(new StubHttp01(), new StubDns01(), new StubDeviceAttest());
    }

    [When(@"I request the validator for a device-attest-01 challenge")]
    public void WhenIRequestValidatorForDeviceAttest()
    {
        Assert.NotNull(_factory);
        _returnedValidator = _factory.GetValidator(CreateChallengeOfType(ChallengeTypes.DeviceAttest01));
    }

    [When(@"I request the validator for a http-01 challenge")]
    public void WhenIRequestValidatorForHttp01()
    {
        Assert.NotNull(_factory);
        _returnedValidator = _factory.GetValidator(CreateChallengeOfType(ChallengeTypes.Http01));
    }

    [When(@"I request the validator for a dns-01 challenge")]
    public void WhenIRequestValidatorForDns01()
    {
        Assert.NotNull(_factory);
        _returnedValidator = _factory.GetValidator(CreateChallengeOfType(ChallengeTypes.Dns01));
    }

    [When(@"I request the validator for an unknown challenge type")]
    public void WhenIRequestValidatorForUnknownType()
    {
        Assert.NotNull(_factory);
        try { _returnedValidator = _factory.GetValidator(CreateChallengeWithUnknownType()); }
        catch (InvalidOperationException ex) { _thrownException = ex; }
    }

    [Then(@"the returned validator implements IValidateDeviceAttestChallenges")]
    public void ThenValidatorImplementsDeviceAttest()
    {
        Assert.NotNull(_returnedValidator);
        Assert.IsType<IValidateDeviceAttestChallenges>(_returnedValidator, exactMatch: false);
    }

    [Then(@"the returned validator implements IValidateHttp01Challenges")]
    public void ThenValidatorImplementsHttp01()
    {
        Assert.NotNull(_returnedValidator);
        Assert.IsType<IValidateHttp01Challenges>(_returnedValidator, exactMatch: false);
    }

    [Then(@"the returned validator implements IValidateDns01Challenges")]
    public void ThenValidatorImplementsDns01()
    {
        Assert.NotNull(_returnedValidator);
        Assert.IsType<IValidateDns01Challenges>(_returnedValidator, exactMatch: false);
    }

    [Then("""
          an InvalidOperationException is thrown with message "(.*)"
          """)]
    public void ThenInvalidOperationExceptionIsThrown(string expectedMessage)
    {
        Assert.NotNull(_thrownException);
        var ex = Assert.IsType<InvalidOperationException>(_thrownException);
        Assert.Equal(expectedMessage, ex.Message);
    }
}
