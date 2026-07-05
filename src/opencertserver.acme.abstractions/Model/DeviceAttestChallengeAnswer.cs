namespace OpenCertServer.Acme.Abstractions.Model;

using System.Text.Json.Serialization;

/// <summary>
/// Represents the attestation proof body sent by an ACME client in response to a device-attest-01 challenge.
/// </summary>
public sealed class DeviceAttestChallengeAnswer
{
    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    [JsonPropertyName("proof")]
    public string Proof { get; set; } = string.Empty;

    [JsonPropertyName("aikCertificate")]
    public string? AikCertificate { get; set; }

    [JsonPropertyName("deviceId")]
    public string? DeviceId { get; set; }
}
