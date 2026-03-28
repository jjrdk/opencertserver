using Microsoft.IdentityModel.Tokens;

namespace OpenCertServer.Acme.Abstractions.HttpModel.Requests;

using System;

/// <summary>
/// Represents the JWS header for an ACME request.
/// </summary>
public sealed class AcmeHeader
{
    /// <summary>
    /// Gets or sets the nonce value for the request.
    /// </summary>
    public string? Nonce { get; set; }
    /// <summary>
    /// Gets or sets the request URL.
    /// </summary>
    public string? Url { get; set; }
    /// <summary>
    /// Gets or sets the signature algorithm.
    /// </summary>
    public string? Alg { get; set; }
    /// <summary>
    /// Gets or sets the key identifier (KID).
    /// </summary>
    public string? Kid { get; set; }
    /// <summary>
    /// Gets or sets the JSON Web Key (JWK) for the request.
    /// </summary>
    public JsonWebKey? Jwk { get; set; }

    /// <summary>
    /// Gets the account ID from the KID or JWK.
    /// </summary>
    /// <returns>The account ID string.</returns>
    /// <exception cref="InvalidOperationException">Thrown if neither KID nor JWK is present.</exception>
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
