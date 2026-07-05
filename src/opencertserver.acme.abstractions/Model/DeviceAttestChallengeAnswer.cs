namespace OpenCertServer.Acme.Abstractions.Model;

using System.Text.Json.Serialization;

/// <summary>
/// Represents the attestation proof body sent by an ACME client in response to a device-attest-01 challenge.
/// </summary>
public sealed class DeviceAttestChallengeAnswer
{
    [JsonPropertyName("nonce")]
    public string Nonce { get; set; } = string.Empty;

    /// <summary>
    /// Base64url-encoded wire bytes of the TPM2B_ATTEST (size-prefixed TPMS_ATTEST) structure.
    /// Contains magic, type, and extraData (nonce) fields that are verified server-side.
    /// </summary>
    [JsonPropertyName("proof")]
    public string Proof { get; set; } = string.Empty;

    /// <summary>
    /// Base64url-encoded RSA-PKCS1v15-SHA256 signature over the <see cref="Proof"/> bytes,
    /// produced by the AIK private key. Used to prove that the AIK key signed the quote.
    /// </summary>
    [JsonPropertyName("signature")]
    public string? Signature { get; set; }

    [JsonPropertyName("aikCertificate")]
    public string? AikCertificate { get; set; }

    [JsonPropertyName("deviceId")]
    public string? DeviceId { get; set; }
}
