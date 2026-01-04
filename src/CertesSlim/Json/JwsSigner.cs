using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace CertesSlim.Json;

/// <summary>
/// Represents an signer for JSON Web Signature.
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
    /// Signs the specified payload.
    /// </summary>
    /// <param name="payload">The payload.</param>
    /// <param name="nonce">The nonce.</param>
    /// <returns>The signed payload.</returns>
    public JwsPayload Sign(object payload, string nonce)
        => Sign(payload, null, null, nonce);

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
                Url = url,
            }
            : new ProtectedHeader
            {
                Alg = ToJwsAlgorithm(_keyPair.Algorithm),
                Kid = keyId,
                Nonce = nonce,
                Url = url,
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

        var payloadEncoded = JwsConvert.ToBase64String(Encoding.UTF8.GetBytes(entityJson));
        var protectedHeaderEncoded = JwsConvert.ToBase64String(Encoding.UTF8.GetBytes(protectedHeaderJson));

        var signature = $"{protectedHeaderEncoded}.{payloadEncoded}";
        var signatureBytes = Encoding.UTF8.GetBytes(signature);
        var signedSignatureBytes = _keyPair.SecurityKey switch
        {
            ECDsaSecurityKey e => e.ECDsa.SignData(signatureBytes, _keyPair.HashAlgorithm),
            RsaSecurityKey r => r.Rsa.SignData(signatureBytes, _keyPair.HashAlgorithm, RSASignaturePadding.Pss),
            _ => throw new NotSupportedException("Unsupported key type."),
        };
//        var signedSignatureBytes =
//            .GetSigner().SignData(signatureBytes);
        //new JsonWebTokenHandler().CreateToken(signature, new SigningCredentials(_keyPair.JsonWebKey,_keyPair.Algorithm));// _keyPair.GetSigner().SignData(signatureBytes);
        var signedSignatureEncoded = JwsConvert.ToBase64String(signedSignatureBytes);

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
        switch (algorithm)
        {
            case SecurityAlgorithms.EcdsaSha256:
                return "ES256";
            case SecurityAlgorithms.EcdsaSha384:
                return "ES384";
            case SecurityAlgorithms.EcdsaSha512:
                return "ES512";
            case SecurityAlgorithms.RsaSha256:
                return "RS256";
            case SecurityAlgorithms.RsaSha384:
                return "RS384";
            case SecurityAlgorithms.RsaSha512:
                return "RS512";
            default:
                throw new ArgumentException(nameof(algorithm));
        }
    }
}
