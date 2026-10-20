using Microsoft.IdentityModel.Tokens;

namespace CertesSlim.Json;

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