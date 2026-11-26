namespace OpenCertServer.Acme.Server.Services;

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.IdentityModel.Tokens;
using OpenCertServer.Acme.Abstractions.Exceptions;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Abstractions.Storage;

/// <summary>
/// Default implementation of <see cref="IExternalAccountBindingService"/>.
/// Validates HMAC-signed EAB JWS objects per RFC 8555 §7.3.4.
/// </summary>
public sealed class DefaultExternalAccountBindingService : IExternalAccountBindingService
{
    private static readonly HashSet<string> SupportedMacAlgorithms =
        new(StringComparer.Ordinal) { "HS256", "HS384", "HS512" };

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
        if (eabJws.ValueKind != JsonValueKind.Object ||
            !eabJws.TryGetProperty("protected", out var protectedProperty) ||
            !eabJws.TryGetProperty("payload", out var payloadProperty) ||
            !eabJws.TryGetProperty("signature", out var signatureProperty))
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding must be a flattened JWS object with 'protected', 'payload', and 'signature'.");
        }

        var protectedEncoded = GetRequiredString(protectedProperty, "protected");
        var payloadEncoded = GetRequiredString(payloadProperty, "payload");
        var signatureEncoded = GetRequiredString(signatureProperty, "signature");

        // 2. Decode and validate the protected header
        string protectedJson;
        try
        {
            protectedJson = Base64UrlEncoder.Decode(protectedEncoded);
        }
        catch (FormatException)
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding 'protected' field could not be base64url-decoded.");
        }

        var alg = string.Empty;
        var kid = string.Empty;
        JsonDocument protectedDoc;
        try
        {
            protectedDoc = JsonDocument.Parse(protectedJson);
        }
        catch (JsonException)
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding 'protected' field could not be parsed as JSON.");
        }

        using (protectedDoc)
        {
            var header = protectedDoc.RootElement;
            if (header.ValueKind != JsonValueKind.Object)
            {
                throw new ExternalAccountBindingException(
                    "The externalAccountBinding protected header must be a JSON object.");
            }

            // 2a. alg must be an HMAC algorithm
            if (!header.TryGetProperty("alg", out var algProperty))
            {
                throw new ExternalAccountBindingException(
                    "The externalAccountBinding protected header must contain an 'alg' claim.");
            }

            alg = algProperty.ValueKind == JsonValueKind.String ? algProperty.GetString() ?? string.Empty : string.Empty;
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

            kid = kidProperty.ValueKind == JsonValueKind.String ? kidProperty.GetString() ?? string.Empty : string.Empty;
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

            var eabUrl = urlProperty.ValueKind == JsonValueKind.String ? urlProperty.GetString() : null;
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

        if (!SupportedMacAlgorithms.Contains(eabKey.MacAlgorithm) ||
            !string.Equals(alg, eabKey.MacAlgorithm, StringComparison.Ordinal))
        {
            throw new ExternalAccountBindingException(
                $"The externalAccountBinding algorithm '{alg}' does not match the provisioned key algorithm.");
        }

        // 4. Verify the HMAC signature
        byte[] macKeyBytes;
        try
        {
            macKeyBytes = Base64UrlEncoder.DecodeBytes(eabKey.MacKey);
        }
        catch (FormatException)
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
        catch (FormatException)
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
        catch (FormatException)
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding 'payload' field could not be base64url-decoded.");
        }

        VerifyPayloadIsAccountJwk(payloadJson, accountJwk);

        if (!await _store.TryConsumeKey(kid, accountId: null, cancellationToken).ConfigureAwait(false))
        {
            throw new ExternalAccountBindingException(
                $"The external account key '{kid}' has already been used and cannot be reused.");
        }

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
        catch (Exception exception) when (exception is JsonException or ArgumentException or InvalidOperationException)
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding payload could not be parsed as a JSON Web Key.");
        }

        string expectedThumbprint;
        string actualThumbprint;
        try
        {
            expectedThumbprint = Base64UrlEncoder.Encode(accountJwk.ComputeJwkThumbprint());
            actualThumbprint = Base64UrlEncoder.Encode(payloadJwk.ComputeJwkThumbprint());
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or
                                           CryptographicException or SecurityTokenException)
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding payload is not a valid JSON Web Key.");
        }

        if (!string.Equals(expectedThumbprint, actualThumbprint, StringComparison.Ordinal))
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding payload does not contain the account's public key.");
        }
    }

    private static JsonWebKey ParseJwk(JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object)
        {
            throw new ExternalAccountBindingException(
                "The externalAccountBinding payload must be a JSON Web Key object.");
        }

        // Build a JsonWebKey from the element's properties
        var jwk = new JsonWebKey();
        if (element.TryGetProperty("kty", out var kty))
        {
            jwk.Kty = kty.GetString();
        }

        if (element.TryGetProperty("crv", out var crv))
        {
            jwk.Crv = crv.GetString();
        }

        if (element.TryGetProperty("x", out var x))
        {
            jwk.X = x.GetString();
        }

        if (element.TryGetProperty("y", out var y))
        {
            jwk.Y = y.GetString();
        }

        if (element.TryGetProperty("n", out var n))
        {
            jwk.N = n.GetString();
        }

        if (element.TryGetProperty("e", out var e))
        {
            jwk.E = e.GetString();
        }

        return jwk;
    }

    private static string GetRequiredString(JsonElement property, string name)
        => property.ValueKind == JsonValueKind.String && property.GetString() is { } value
            ? value
            : throw new ExternalAccountBindingException(
                $"The externalAccountBinding '{name}' field must be a string.");

    private static HMAC CreateHmac(string algorithm, byte[] key)
        => algorithm.ToUpperInvariant() switch
        {
            "HS256" => new HMACSHA256(key),
            "HS384" => new HMACSHA384(key),
            "HS512" => new HMACSHA512(key),
            _ => throw new NotSupportedException($"HMAC algorithm '{algorithm}' is not supported.")
        };
}