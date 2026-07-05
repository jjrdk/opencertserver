using System.Text.Json;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Services;
using Reqnroll;
using Xunit;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

/// <summary>
/// Step definitions for device-attest-models.feature (GROUP 1).
/// Tests model serialization and interface hierarchy.
/// </summary>
[Binding]
public sealed class DeviceAttestModelsSteps
{
    private DeviceAttestChallengeAnswer? _answer;
    private string? _json;

    [Given("""
           a DeviceAttestChallengeAnswer with Nonce "(.*)" Proof "(.*)" AikCertificate "(.*)" DeviceId "(.*)"
           """)]
    public void GivenADeviceAttestChallengeAnswerWith(string nonce, string proof, string aikCertificate, string deviceId)
    {
        _answer = new DeviceAttestChallengeAnswer
        {
            Nonce = nonce,
            Proof = proof,
            AikCertificate = aikCertificate,
            DeviceId = deviceId
        };
    }

    [When(@"serialized to JSON")]
    public void WhenSerializedToJson()
    {
        Assert.NotNull(_answer);
        _json = JsonSerializer.Serialize(_answer);
    }

    [Then("""
          the JSON contains nonce "(.*)"
          """)]
    public void ThenTheJsonContainsNonce(string expected) =>
        Assert.Contains($"\"nonce\":\"{expected}\"", _json);

    [Then("""
          the JSON contains proof "(.*)"
          """)]
    public void ThenTheJsonContainsProof(string expected) =>
        Assert.Contains($"\"proof\":\"{expected}\"", _json);

    [Then("""
          the JSON contains aikCertificate "(.*)"
          """)]
    public void ThenTheJsonContainsAikCertificate(string expected) =>
        Assert.Contains($"\"aikCertificate\":\"{expected}\"", _json);

    [Then("""
          the JSON contains deviceId "(.*)"
          """)]
    public void ThenTheJsonContainsDeviceId(string expected) =>
        Assert.Contains($"\"deviceId\":\"{expected}\"", _json);

    [Given("""
           a JSON string with nonce "(.*)" proof "(.*)" aikCertificate "(.*)" deviceId "(.*)"
           """)]
    public void GivenAJsonStringWith(string nonce, string proof, string aikCertificate, string deviceId)
    {
        _json = $"{{\"nonce\":\"{nonce}\",\"proof\":\"{proof}\",\"aikCertificate\":\"{aikCertificate}\",\"deviceId\":\"{deviceId}\"}}";
    }

    [When(@"deserialized to DeviceAttestChallengeAnswer")]
    public void WhenDeserializedToDeviceAttestChallengeAnswer()
    {
        Assert.NotNull(_json);
        _answer = JsonSerializer.Deserialize<DeviceAttestChallengeAnswer>(_json);
    }

    [Then("""
          the Nonce property is "(.*)"
          """)]
    public void ThenTheNoncePropertyIs(string expected)
    {
        Assert.NotNull(_answer);
        Assert.Equal(expected, _answer.Nonce);
    }

    [Then("""
          the Proof property is "(.*)"
          """)]
    public void ThenTheProofPropertyIs(string expected)
    {
        Assert.NotNull(_answer);
        Assert.Equal(expected, _answer.Proof);
    }

    [Then("""
          the AikCertificate property is "(.*)"
          """)]
    public void ThenTheAikCertificatePropertyIs(string expected)
    {
        Assert.NotNull(_answer);
        Assert.Equal(expected, _answer.AikCertificate);
    }

    [Then("""
          the DeviceId property is "(.*)"
          """)]
    public void ThenTheDeviceIdPropertyIs(string expected)
    {
        Assert.NotNull(_answer);
        Assert.Equal(expected, _answer.DeviceId);
    }

    [When(@"I inspect the IValidateDeviceAttestChallenges type via reflection")]
    public void WhenIInspectTheInterfaceViaReflection()
    {
        // No state needed; the Then step does the inspection
    }

    [Then(@"it implements IValidateChallenges")]
    public void ThenItImplementsIValidateChallenges()
    {
        Assert.True(
            typeof(IValidateChallenges).IsAssignableFrom(typeof(IValidateDeviceAttestChallenges)),
            "IValidateDeviceAttestChallenges must extend IValidateChallenges");
    }
}
