namespace OpenCertServer.Acme.Server.Tests.StepDefinitions;

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Reflection;
using CertesSlim.Acme.Resource;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server.Services;
using Reqnroll;
using Xunit;
using AcmeAccount = OpenCertServer.Acme.Abstractions.Model.Account;
using AcmeChallenge = OpenCertServer.Acme.Abstractions.Model.Challenge;
using AcmeError = OpenCertServer.Acme.Abstractions.Model.AcmeError;
using AcmeIdentifier = OpenCertServer.Acme.Abstractions.Model.Identifier;
using AcmeOrder = OpenCertServer.Acme.Abstractions.Model.Order;
using AcmeAuthorization = OpenCertServer.Acme.Abstractions.Model.Authorization;
using DeviceAttestAnswer = OpenCertServer.Acme.Abstractions.Model.DeviceAttestChallengeAnswer;

/// <summary>
/// Step definitions for device-attest-validation.feature (GROUP 2).
/// Tests the DeviceAttestChallengeValidator directly.
/// </summary>
[Binding]
public sealed class DeviceAttestValidationSteps
{
    private AcmeChallenge? _challenge;
    private AcmeAccount? _account;
    private bool _resultIsValid;
    private AcmeError? _resultError;

    private static readonly FieldInfo TokenBackingField =
        typeof(AcmeChallenge).GetField("<Token>k__BackingField",
            BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("Cannot find Token backing field on Challenge");

    private static AcmeAccount CreateTestAccount()
    {
        using var rsa = RSA.Create(2048);
        var securityKey = new RsaSecurityKey(rsa.ExportParameters(true));
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
        return new AcmeAccount(jwk, null, DateTimeOffset.UtcNow) { Status = AccountStatus.Valid };
    }

    private static AcmeChallenge CreateChallengeWithToken(string token)
    {
        var account = CreateTestAccount();
        var order = new AcmeOrder(account, [new AcmeIdentifier("dns", "test.example.com")], null)
        {
            Expires = DateTimeOffset.UtcNow.AddDays(1)
        };
        var authorization = new AcmeAuthorization(order, new AcmeIdentifier("dns", "test.example.com"),
            DateTimeOffset.UtcNow.AddDays(1));

        var challenge = new AcmeChallenge(authorization, ChallengeTypes.DeviceAttest01);
        TokenBackingField.SetValue(challenge, token);
        return challenge;
    }

    private static string CreateTestAikCertificateBase64Url()
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test AIK", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return Convert.ToBase64String(cert.Export(X509ContentType.Cert))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');
    }

    private static string BuildExtraData(string nonce, string? aikCertificate = null)
    {
        var answer = new DeviceAttestAnswer
        {
            Nonce = nonce,
            Proof = "dGVzdHByb29m",
            AikCertificate = aikCertificate
        };
        return JsonSerializer.Serialize(answer);
    }

    [Given(@"a device-attest-01 challenge with token ""(.*)""")]
    public void GivenAChallengeWithToken(string token)
    {
        _account = CreateTestAccount();
        _challenge = CreateChallengeWithToken(token);
    }

    [Given(@"the challenge has extra data with matching nonce ""(.*)"" and a valid AIK certificate")]
    public void GivenTheChallengeHasExtraDataWithMatchingNonceAndValidAik(string nonce)
    {
        Assert.NotNull(_challenge);
        _challenge.ExtraData = BuildExtraData(nonce, CreateTestAikCertificateBase64Url());
    }

    [Given(@"the challenge has extra data with a different nonce ""(.*)""")]
    public void GivenTheChallengeHasExtraDataWithDifferentNonce(string differentNonce)
    {
        Assert.NotNull(_challenge);
        _challenge.ExtraData = BuildExtraData(differentNonce, CreateTestAikCertificateBase64Url());
    }

    [Given(@"the challenge has no extra data")]
    public void GivenTheChallengeHasNoExtraData()
    {
        Assert.NotNull(_challenge);
        _challenge.ExtraData = null;
    }

    [Given(@"the challenge has extra data with matching nonce ""(.*)"" but no AIK certificate")]
    public void GivenTheChallengeHasExtraDataWithMatchingNonceButNoAik(string nonce)
    {
        Assert.NotNull(_challenge);
        _challenge.ExtraData = BuildExtraData(nonce, aikCertificate: null);
    }

    [When(@"the server validates the challenge")]
    public async Task WhenTheServerValidatesTheChallenge()
    {
        Assert.NotNull(_challenge);
        var validator = new DeviceAttestChallengeValidator();
        (_resultIsValid, _resultError) = await validator.ValidateChallenge(
            _challenge, _account ?? CreateTestAccount(), CancellationToken.None);
    }

    [Then(@"the result is valid")]
    public void ThenTheResultIsValid() =>
        Assert.True(_resultIsValid, $"Expected valid but got error: {_resultError?.Type}: {_resultError?.Detail}");

    [Then(@"there is no error")]
    public void ThenThereIsNoError() => Assert.Null(_resultError);

    [Then(@"the result is not valid")]
    public void ThenTheResultIsNotValid() => Assert.False(_resultIsValid);

    [Then(@"the error type contains ""(.*)""")]
    public void ThenTheErrorTypeContains(string expectedType)
    {
        Assert.NotNull(_resultError);
        Assert.Contains(expectedType, _resultError.Type, StringComparison.OrdinalIgnoreCase);
    }
}
