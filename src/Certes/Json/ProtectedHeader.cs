using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace Certes.Json;

internal class ProtectedHeader
{
    [JsonPropertyName("alg")] public required string Alg { get; set; }
    [JsonPropertyName("jwk")] public JsonWebKey? Jwk { get; set; }
    [JsonPropertyName("kid")] public Uri? Kid { get; set; }
    [JsonPropertyName("nonce")] public string? Nonce { get; set; }
    [JsonPropertyName("url")] public Uri? Url { get; set; }
}
