using CertesSlim.Acme;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Reflection;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server.Services;
using Reqnroll;
using Xunit;
using AcmeAccount = Acme.Abstractions.Model.Account;
using AcmeChallenge = Acme.Abstractions.Model.Challenge;
using AcmeOrder = Acme.Abstractions.Model.Order;
using AcmeAuthorization = Acme.Abstractions.Model.Authorization;

[Binding]
public sealed class DeviceAttestFactorySteps
{
    private DefaultChallengeValidatorFactory? _factory;
    private IValidateChallenges? _returnedValidator;
    private Exception? _thrownException;

    private sealed class StubHttp01 : IValidateChallenges
    {
        public string AppliesTo => ChallengeTypes.Http01;

        public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            AcmeChallenge challenge,
            AcmeAccount account,
            CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private sealed class StubDns01 : IValidateChallenges
    {
        public string AppliesTo => ChallengeTypes.Dns01;

        public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            AcmeChallenge challenge,
            AcmeAccount account,
            CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private sealed class StubDeviceAttest : IValidateChallenges
    {
        public string AppliesTo => ChallengeTypes.DeviceAttest01;

        public Task<(bool IsValid, AcmeError? error)> ValidateChallenge(
            AcmeChallenge challenge,
            AcmeAccount account,
            CancellationToken cancellationToken)
            => Task.FromResult<(bool, AcmeError?)>((true, null));
    }

    private static AcmeChallenge CreateChallengeOfType(string type)
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var securityKey = new RsaSecurityKey(rsa.ExportParameters(true));
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
        var account = new AcmeAccount(jwk, null, null) { Status = AccountStatus.Valid };
        var order = new AcmeOrder(account, [new Identifier { Type = IdentifierType.Dns, Value = "test.example.com" }],
            null)
        {
            Expires = DateTimeOffset.UtcNow.AddDays(1)
        };
        var authorization = new AcmeAuthorization(order,
            new Identifier { Type = IdentifierType.Dns, Value = "test.example.com" },
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
        _factory = new DefaultChallengeValidatorFactory([new StubHttp01(), new StubDns01(), new StubDeviceAttest()]);
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
        try
        {
            _returnedValidator = _factory.GetValidator(CreateChallengeWithUnknownType());
        }
        catch (InvalidOperationException ex)
        {
            _thrownException = ex;
        }
    }

    [Then(@"the returned validator applies to device-attest-01")]
    public void ThenValidatorAppliesToDeviceAttest()
    {
        Assert.NotNull(_returnedValidator);
        Assert.Equal(ChallengeTypes.DeviceAttest01, _returnedValidator.AppliesTo);
    }

    [Then(@"the returned validator applies to http-01")]
    public void ThenValidatorAppliesToHttp01()
    {
        Assert.NotNull(_returnedValidator);
        Assert.Equal(ChallengeTypes.Http01, _returnedValidator.AppliesTo);
    }

    [Then(@"the returned validator applies to dns-01")]
    public void ThenValidatorAppliesToDns01()
    {
        Assert.NotNull(_returnedValidator);
        Assert.Equal(ChallengeTypes.Dns01, _returnedValidator.AppliesTo);
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
