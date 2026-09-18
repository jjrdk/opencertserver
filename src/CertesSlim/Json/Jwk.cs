namespace CertesSlim.Json;

using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

internal class Jwk
{
    [JsonPropertyName("kty")] public required string Kty { get; set; }
    [JsonPropertyName("crv")] public string? Crv { get; set; }
    [JsonPropertyName("x")] public string? X { get; set; }
    [JsonPropertyName("y")] public string? Y { get; set; }
    [JsonPropertyName("n")] public string? N { get; set; }
    [JsonPropertyName("e")] public string? E { get; set; }
}

internal static class JwkConverter
{
    public static Jwk FromJsonWebKey(JsonWebKey jwk)
    {
        return new Jwk
        {
            Kty = jwk.Kty,
            Crv = jwk.Crv,
            X = jwk.X,
            Y = jwk.Y,
            N = jwk.N,
            E = jwk.E
        };
    }
}