namespace CertesSlim.Acme.Resource;

using System.Text.Json.Serialization;

/// <summary>Represents the flattened JWS for ACME External Account Binding.</summary>
public sealed class ExternalAccountBinding
{
    /// <summary>Gets or sets the base64url-encoded protected header.</summary>
    [JsonPropertyName("protected")]
    public string Protected { get; set; } = string.Empty;

    /// <summary>Gets or sets the base64url-encoded account JWK payload.</summary>
    [JsonPropertyName("payload")]
    public string Payload { get; set; } = string.Empty;

    /// <summary>Gets or sets the base64url-encoded HMAC signature.</summary>
    [JsonPropertyName("signature")]
    public string Signature { get; set; } = string.Empty;
}
