using Microsoft.IdentityModel.Tokens;

namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

using System;
using System.Text.Json.Serialization;

public sealed class AcmeHeader
{
    public string? Nonce { get; set; }
    public string? Url { get; set; }

    public string? Alg { get; set; }
    public string? Kid { get; set; }

    public JsonWebKey? Jwk { get; set; }

    public string GetAccountId()
    {
        var kid = Kid ?? Jwk?.Kid;
        if (kid == null)
        {
            throw new InvalidOperationException();
        }

        var lastIndex = kid.LastIndexOf('/');
        return lastIndex == -1 ? kid : kid[(lastIndex + 1)..];
    }
}
