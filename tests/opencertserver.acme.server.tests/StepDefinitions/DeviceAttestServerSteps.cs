namespace OpenCertServer.Acme.Server.Tests.StepDefinitions;

using System;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using CertesSlim.Acme.Resource;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.Services;
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
/// Step definitions for device-attest-directory.feature (GROUP 4) and
/// device-attest-e2e.feature (GROUP 5).
/// </summary>
[Binding]
public sealed class DeviceAttestServerSteps : IDisposable
{
    private TestServer? _server;
    private JsonObject? _directoryJson;
    private AcmeChallenge? _challenge;
    private AcmeAccount? _account;
    private bool _challengeIsValid;
    private AcmeError? _challengeError;

    private static readonly FieldInfo TokenBackingField =
        typeof(AcmeChallenge).GetField("<Token>k__BackingField",
            BindingFlags.Instance | BindingFlags.NonPublic)
        ?? throw new InvalidOperationException("Cannot find Token backing field on Challenge");

    // ─── GROUP 4 & 5: Server setup ────────────────────────────────────────────

    [Given(@"an initialized ACME server with device-attest-01 wired up")]
    public void GivenAnInitializedAcmeServerWithDeviceAttest01WiredUp()
    {
        _server = TestAcmeServerFactory.Create();
    }

    // ─── GROUP 4: Directory steps ─────────────────────────────────────────────

    [When(@"I GET the directory endpoint")]
    public async Task WhenIGetTheDirectoryEndpoint()
    {
        Assert.NotNull(_server);
        var response = await _server.CreateClient().GetAsync(new Uri("https://localhost/directory"));
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        _directoryJson = JsonSerializer.Deserialize<JsonObject>(json)
            ?? throw new InvalidOperationException("Directory response was not a JSON object");
    }

    [Then(@"the response contains a meta field")]
    public void ThenTheResponseContainsAMetaField()
    {
        Assert.NotNull(_directoryJson);
        Assert.True(_directoryJson.ContainsKey("meta"), "Directory must contain 'meta' field");
    }

    [Then(@"the challengeTypesWithAdditionalContent array includes ""(.*)""")]
    public void ThenTheChallengeTypesWithAdditionalContentIncludes(string expectedType)
    {
        Assert.NotNull(_directoryJson);
        var meta = _directoryJson["meta"]?.AsObject()
            ?? throw new InvalidOperationException("'meta' is not an object");
        var challengeTypes = meta["challengeTypesWithAdditionalContent"]?.AsArray()
            ?? throw new InvalidOperationException("'challengeTypesWithAdditionalContent' not found in meta");
        var types = challengeTypes.Select(n => n?.GetValue<string>() ?? string.Empty).ToList();
        Assert.Contains(expectedType, types);
    }

    // ─── GROUP 5: E2E steps ───────────────────────────────────────────────────

    [Given(@"a device-attest-01 challenge exists with token ""(.*)""")]
    public void GivenAChallengeExistsWithToken(string token)
    {
        using var rsa = RSA.Create(2048);
        var securityKey = new RsaSecurityKey(rsa.ExportParameters(true));
        var jwk = JsonWebKeyConverter.ConvertFromRSASecurityKey(securityKey);
        _account = new AcmeAccount(jwk, null, DateTimeOffset.UtcNow) { Status = AccountStatus.Valid };
        var order = new AcmeOrder(_account, [new AcmeIdentifier("dns", "device.example.com")], null)
        {
            Expires = DateTimeOffset.UtcNow.AddDays(1)
        };
        var authorization = new AcmeAuthorization(order, new AcmeIdentifier("dns", "device.example.com"),
            DateTimeOffset.UtcNow.AddDays(1));
        _challenge = new AcmeChallenge(authorization, ChallengeTypes.DeviceAttest01);
        TokenBackingField.SetValue(_challenge, token);
    }

    [When(@"the device submits attestation evidence with matching nonce ""(.*)"" and a valid AIK certificate")]
    public async Task WhenTheDeviceSubmitsAttestationEvidence(string nonce)
    {
        Assert.NotNull(_challenge);
        Assert.NotNull(_server);
        Assert.NotNull(_account);

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=Test AIK", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        var aikCert = Convert.ToBase64String(cert.Export(X509ContentType.Cert))
            .Replace('+', '-').Replace('/', '_').TrimEnd('=');

        _challenge.ExtraData = JsonSerializer.Serialize(new DeviceAttestAnswer
        {
            Nonce = nonce,
            Proof = "dGVzdHByb29m",
            AikCertificate = aikCert
        });

        using var scope = _server.Services.CreateScope();
        var validator = scope.ServiceProvider.GetRequiredService<IValidateDeviceAttestChallenges>();
        (_challengeIsValid, _challengeError) = await validator.ValidateChallenge(
            _challenge, _account, CancellationToken.None);
    }

    [Then(@"the challenge is marked as valid")]
    public void ThenTheChallengeIsMarkedAsValid()
    {
        Assert.True(_challengeIsValid,
            $"Validation failed: {_challengeError?.Type}: {_challengeError?.Detail}");
    }

    [Then(@"no ACME error is recorded")]
    public void ThenNoAcmeErrorIsRecorded() => Assert.Null(_challengeError);

    public void Dispose() => _server?.Dispose();
}
