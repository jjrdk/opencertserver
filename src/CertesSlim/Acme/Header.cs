using System.Text.Json.Serialization;

namespace CertesSlim.Acme;

internal class Header
{
    [JsonPropertyName("alg")] public required string Alg { get; set; }
    [JsonPropertyName("kid")] public required string Kid { get; set; }
    [JsonPropertyName("url")] public required Uri Url { get; set; }
}
