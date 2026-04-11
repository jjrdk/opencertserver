using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.Exceptions;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Abstractions.Storage;

namespace OpenCertServer.Acme.Server.Services;

/// <summary>
/// Default implementation of <see cref="IExternalAccountBindingService"/>.
/// Validates HMAC-signed EAB JWS objects per RFC 8555 §7.3.4.
/// </summary>
public sealed class DefaultExternalAccountBindingService : IExternalAccountBindingService
{
    private static readonly HashSet<string> SupportedMacAlgorithms =
        new(StringComparer.OrdinalIgnoreCase) { "HS256", "HS384", "HS512" };

    private readonly IStoreExternalAccountKeys _store;

    public DefaultExternalAccountBindingService(IStoreExternalAccountKeys store)
    {
        _store = store;
    }

    /// <inheritdoc />
    public async Task<string> ValidateAsync(
        JsonElement eabJws,
        JsonWebKey accountJwk,
        string requestUrl,
        CancellationToken cancellationToken)
    {
        // 1. Parse the flattened JWS envelope
        if (!eabJws.TryGetProperty("protected", out var protectedProperty) ||
            !eabJws.TryGetProperty("payload", out var payloadProperty) ||
            !eabJws.TryGetProperty("signature", out var signatureProperty))
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding must be a flattened JWS object with 'protected', 'payload', and 'signature'.");
        }

        var protectedEncoded = protectedProperty.GetString()
            ?? throw new ExternalAccountBindingException("The externalAccountBinding 'protected' field is null.");
        var payloadEncoded = payloadProperty.GetString()
            ?? throw new ExternalAccountBindingException("The externalAccountBinding 'payload' field is null.");
        var signatureEncoded = signatureProperty.GetString()
            ?? throw new ExternalAccountBindingException("The externalAccountBinding 'signature' field is null.");

        // 2. Decode and validate the protected header
        string protectedJson;
        try
        {
            protectedJson = Base64UrlEncoder.Decode(protectedEncoded);
        }
        catch
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding 'protected' field could not be base64url-decoded.");
        }

        string alg = string.Empty;
        string kid = string.Empty;
        JsonDocument protectedDoc;
        try
        {
            protectedDoc = JsonDocument.Parse(protectedJson);
        }
        catch
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding 'protected' field could not be parsed as JSON.");
        }

        using (protectedDoc)
        {
            var header = protectedDoc.RootElement;

            // 2a. alg must be an HMAC algorithm
            if (!header.TryGetProperty("alg", out var algProperty))
            {
                throw new ExternalAccountBindingException(
                    "The externalAccountBinding protected header must contain an 'alg' claim.");
            }

            alg = algProperty.GetString() ?? string.Empty;
            if (!SupportedMacAlgorithms.Contains(alg))
            {
                throw new ExternalAccountBindingException(
                    $"The externalAccountBinding algorithm '{alg}' is not supported. Supported algorithms: {string.Join(", ", SupportedMacAlgorithms)}.");
            }

            // 2b. kid must be present
            if (!header.TryGetProperty("kid", out var kidProperty))
            {
                throw new ExternalAccountBindingException(
                    "The externalAccountBinding protected header must contain a 'kid' claim.");
            }

            kid = kidProperty.GetString() ?? string.Empty;
            if (string.IsNullOrWhiteSpace(kid))
            {
                throw new ExternalAccountBindingException(
                    "The externalAccountBinding protected header 'kid' claim must not be empty.");
            }

            // 2c. url must match the request URL
            if (!header.TryGetProperty("url", out var urlProperty))
            {
                throw new ExternalAccountBindingException(
                    "The externalAccountBinding protected header must contain a 'url' claim.");
            }

            var eabUrl = urlProperty.GetString();
            if (!string.Equals(eabUrl, requestUrl, StringComparison.Ordinal))
            {
                throw new ExternalAccountBindingException(
                    $"The externalAccountBinding 'url' claim '{eabUrl}' does not match the request URL '{requestUrl}'.");
            }
        }

        // 3. Look up the external account key
        var eabKey = await _store.LoadKey(kid, cancellationToken).ConfigureAwait(false);
        if (eabKey == null)
        {
            throw new ExternalAccountBindingException(
                $"No external account key found for kid '{kid}'.");
        }

        if (eabKey.IsUsed)
        {
            throw new ExternalAccountBindingException(
                $"The external account key '{kid}' has already been used and cannot be reused.");
        }

        // 4. Verify the HMAC signature
        byte[] macKeyBytes;
        try
        {
            macKeyBytes = Base64UrlEncoder.DecodeBytes(eabKey.MacKey);
        }
        catch
        {
            throw new ExternalAccountBindingException(
                "The external account key MAC key could not be decoded.");
        }

        var signingInput = Encoding.ASCII.GetBytes($"{protectedEncoded}.{payloadEncoded}");
        using var hmac = CreateHmac(alg, macKeyBytes);
        var expectedSignature = hmac.ComputeHash(signingInput);
        byte[] actualSignature;
        try
        {
            actualSignature = Base64UrlEncoder.DecodeBytes(signatureEncoded);
        }
        catch
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding 'signature' could not be base64url-decoded.");
        }

        if (!CryptographicOperations.FixedTimeEquals(expectedSignature, actualSignature))
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding HMAC signature is invalid.");
        }

        // 5. Verify the payload contains the account public key
        string payloadJson;
        try
        {
            payloadJson = Base64UrlEncoder.Decode(payloadEncoded);
        }
        catch
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding 'payload' field could not be base64url-decoded.");
        }

        VerifyPayloadIsAccountJwk(payloadJson, accountJwk);

        return kid;
    }

    /// <inheritdoc />
    public async Task<bool> HasActiveKeyAsync(string keyId, CancellationToken cancellationToken)
    {
        var key = await _store.FindActiveKey(keyId, cancellationToken).ConfigureAwait(false);
        return key != null;
    }

    private static void VerifyPayloadIsAccountJwk(string payloadJson, JsonWebKey accountJwk)
    {
        // The EAB payload must be the account JWK. We compare JWK thumbprints for robustness.
        JsonWebKey payloadJwk;
        try
        {
            using var payloadDoc = JsonDocument.Parse(payloadJson);
            // Re-serialize through JsonWebKey to normalise the key representation
            payloadJwk = ParseJwk(payloadDoc.RootElement);
        }
        catch (ExternalAccountBindingException)
        {
            throw;
        }
        catch
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding payload could not be parsed as a JSON Web Key.");
        }

        var expectedThumbprint = Base64UrlEncoder.Encode(accountJwk.ComputeJwkThumbprint());
        var actualThumbprint = Base64UrlEncoder.Encode(payloadJwk.ComputeJwkThumbprint());

        if (!string.Equals(expectedThumbprint, actualThumbprint, StringComparison.Ordinal))
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding payload does not contain the account's public key.");
        }
    }

    private static JsonWebKey ParseJwk(JsonElement element)
    {
        // Build a JsonWebKey from the element's properties
        var jwk = new JsonWebKey();
        if (element.TryGetProperty("kty", out var kty)) jwk.Kty = kty.GetString();
        if (element.TryGetProperty("crv", out var crv)) jwk.Crv = crv.GetString();
        if (element.TryGetProperty("x", out var x)) jwk.X = x.GetString();
        if (element.TryGetProperty("y", out var y)) jwk.Y = y.GetString();
        if (element.TryGetProperty("n", out var n)) jwk.N = n.GetString();
        if (element.TryGetProperty("e", out var e)) jwk.E = e.GetString();
        return jwk;
    }

    private static HMAC CreateHmac(string algorithm, byte[] key)
        => algorithm.ToUpperInvariant() switch
        {
            "HS256" => new HMACSHA256(key),
            "HS384" => new HMACSHA384(key),
            "HS512" => new HMACSHA512(key),
            _ => throw new NotSupportedException($"HMAC algorithm '{algorithm}' is not supported.")
        };
}

