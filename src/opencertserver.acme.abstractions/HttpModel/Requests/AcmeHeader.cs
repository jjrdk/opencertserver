namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests
{
    using System;
    using System.Text.Json.Serialization;
    using Converters;
    using Model;

    public class AcmeHeader
    {
        public string? Nonce { get; set; }
        public string? Url { get; set; }

        public string? Alg { get; set; }
        public string? Kid { get; set; }

        [JsonConverter(typeof(JwkConverter))]
        public Jwk? Jwk { get; set; }

        public string GetAccountId()
        {
            var kid = Kid ?? Jwk?.SecurityKey.Kid ?? Jwk?.KeyHash;
            if (kid == null)
            {
                throw new InvalidOperationException();
            }

            var lastIndex = kid.LastIndexOf('/');
            return lastIndex == -1 ? kid : kid[(lastIndex + 1)..];//.Split('/').Last();
        }
    }
}
