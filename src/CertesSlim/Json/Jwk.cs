namespace CertesSlim.Json;

using System.Text.Json.Serialization;

internal class Jwk
{
    [JsonPropertyName("kty")] public required string Kty { get; set; }
    [JsonPropertyName("crv")] public string? Crv { get; set; }
    [JsonPropertyName("x")] public string? X { get; set; }
    [JsonPropertyName("y")] public string? Y { get; set; }
    [JsonPropertyName("n")] public string? N { get; set; }
    [JsonPropertyName("e")] public string? E { get; set; }
}