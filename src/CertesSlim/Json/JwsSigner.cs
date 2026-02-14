using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Microsoft.IdentityModel.Tokens;

namespace CertesSlim.Json;

/// <summary>
/// Represents a signer for JSON Web Signature.
/// </summary>
internal class JwsSigner
{
    private readonly IKey _keyPair;

    /// <summary>
    /// Initializes a new instance of the <see cref="JwsSigner"/> class.
    /// </summary>
    /// <param name="keyPair">The keyPair.</param>
    public JwsSigner(IKey keyPair)
    {
        _keyPair = keyPair;
    }

    /// <summary>
    /// Encodes this instance.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="keyId">The key identifier.</param>
    /// <param name="url">The URL.</param>
    /// <param name="nonce">The nonce.</param>
    /// <returns>The signed payload.</returns>
    public JwsPayload Sign<T>(
        T payload,
        Uri? keyId = null,
        Uri? url = null,
        string? nonce = null)
    {
        var protectedHeader = keyId == null
            ? new ProtectedHeader
            {
                Alg = ToJwsAlgorithm(_keyPair.Algorithm),
                Jwk = _keyPair.JsonWebKey,
                Nonce = nonce,
                Url = url
            }
            : new ProtectedHeader
            {
                Alg = ToJwsAlgorithm(_keyPair.Algorithm),
                Kid = keyId,
                Nonce = nonce,
                Url = url
            };

        var entityJson = "";
        if (payload != null)
        {
            var typeInfo = (JsonTypeInfo<T>)CertesSerializerContext.Default.GetTypeInfo(typeof(T))!;
            entityJson = JsonSerializer.Serialize(payload,
                typeInfo);
        }

        var protectedHeaderJson =
            JsonSerializer.Serialize(protectedHeader, CertesSerializerContext.Default.ProtectedHeader);

        var payloadEncoded = Encoding.UTF8.GetBytes(entityJson).ToBase64String();
        var protectedHeaderEncoded = Encoding.UTF8.GetBytes(protectedHeaderJson).ToBase64String();

        var signature = $"{protectedHeaderEncoded}.{payloadEncoded}";
        var signatureBytes = Encoding.UTF8.GetBytes(signature);
        var signedSignatureBytes = _keyPair.SecurityKey switch
        {
            ECDsaSecurityKey e => e.ECDsa.SignData(signatureBytes, _keyPair.HashAlgorithm),
            RsaSecurityKey r => r.Rsa.SignData(signatureBytes, _keyPair.HashAlgorithm, RSASignaturePadding.Pss),
            _ => throw new NotSupportedException("Unsupported key type.")
        };
        var signedSignatureEncoded = signedSignatureBytes.ToBase64String();

        var body = new JwsPayload
        {
            Protected = protectedHeaderEncoded,
            Payload = payloadEncoded,
            Signature = signedSignatureEncoded
        };

        return body;
    }

    /// <summary>
    /// Get the JWS name of the <paramref name="algorithm"/>.
    /// </summary>
    /// <param name="algorithm">The algorithm.</param>
    /// <returns></returns>
    private static string ToJwsAlgorithm(string algorithm)
    {
        return algorithm switch
        {
            SecurityAlgorithms.EcdsaSha256 => "ES256",
            SecurityAlgorithms.EcdsaSha384 => "ES384",
            SecurityAlgorithms.EcdsaSha512 => "ES512",
            SecurityAlgorithms.RsaSha256 => "RS256",
            SecurityAlgorithms.RsaSha384 => "RS384",
            SecurityAlgorithms.RsaSha512 => "RS512",
            _ => throw new ArgumentException(nameof(algorithm))
        };
    }
}
