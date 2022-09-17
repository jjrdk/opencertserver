namespace OpenCertServer.Acme.Abstractions.Model
{
    using Exceptions;
    using Microsoft.IdentityModel.Tokens;

    public sealed class Jwk
    {
        private JsonWebKey? _jsonWebKey;
        
        private string? _jsonKeyHash;
        private string? _json;

        private Jwk() { }

        public Jwk(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
            {
                throw new System.ArgumentNullException(nameof(json));
            }

            Json = json;
        }

        public string Json
        {
            get { return _json ?? throw new NotInitializedException(); }
            set { _json = value; }
        }

        public JsonWebKey SecurityKey
        {
            get { return _jsonWebKey ??= JsonWebKey.Create(Json); }
        }

        public string KeyHash
        {
            get { return _jsonKeyHash ??= Base64UrlEncoder.Encode(SecurityKey.ComputeJwkThumbprint()); }
        }
    }
}
