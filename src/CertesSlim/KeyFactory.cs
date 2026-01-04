namespace CertesSlim;

using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Provides helper methods for handling keys.
/// </summary>
public static class KeyFactory
{
    /// <summary>
    /// Creates a random key.
    /// </summary>
    /// <param name="algorithm">The algorithm to use.</param>
    /// <param name="keySize">Optional key size (used for RSA, defaults to 2048)</param>
    /// <returns>The key created.</returns>
    public static IKey NewKey(string algorithm, int? keySize = null)
    {
        switch (algorithm)
        {
            case SecurityAlgorithms.EcdsaSha256:
                var jwk = new ECDsaSecurityKey(ECDsa.Create());
                return new Key(SecurityAlgorithms.EcdsaSha256, jwk, HashAlgorithmName.SHA256);
            case SecurityAlgorithms.EcdsaSha384:
                var ecdsa384Jwk = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP384));
                return new Key(SecurityAlgorithms.EcdsaSha384, ecdsa384Jwk, HashAlgorithmName.SHA384);
            case SecurityAlgorithms.EcdsaSha512:
                var ecdsa512Jwk = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP521));
                return new Key(SecurityAlgorithms.EcdsaSha512, ecdsa512Jwk, HashAlgorithmName.SHA512);
            case SecurityAlgorithms.RsaSha256:
                var rsaJwk = new RsaSecurityKey(RSA.Create(keySize ?? 2048));
                return new Key(SecurityAlgorithms.RsaSha256, rsaJwk, HashAlgorithmName.SHA256);
            case SecurityAlgorithms.RsaSha384:
                var rsa384Jwk = new RsaSecurityKey(RSA.Create(keySize ?? 2048));
                return new Key(SecurityAlgorithms.RsaSha384, rsa384Jwk, HashAlgorithmName.SHA384);
            case SecurityAlgorithms.RsaSha512:
                var rsa512Jwk = new RsaSecurityKey(RSA.Create(keySize ?? 2048));
                return new Key(SecurityAlgorithms.RsaSha512, rsa512Jwk, HashAlgorithmName.SHA512);
            default:
                throw new NotSupportedException($"The algorithm '{algorithm}' is not supported.");
        }
    }

    /// <summary>
    /// Parse the key from PEM encoded text.
    /// </summary>
    /// <param name="pem">The PEM encoded text.</param>
    /// <returns>The key restored.</returns>
    public static IKey FromPem(string pem)
    {
        AsymmetricAlgorithm key = pem.StartsWith("-----BEGIN RSA") || pem.StartsWith("-----BEGIN PRIVATE KEY")
            ? RSA.Create()
            : ECDsa.Create();
        key.ImportFromPem(pem); // X509Certificate2.CreateFromPem(pem);
        SecurityKey jwk = key switch
        {
            ECDsa e => new ECDsaSecurityKey(e),
            RSA r => new RsaSecurityKey(r),
            _ => throw new NotSupportedException("Only RSA and ECDsa keys are supported."),
        };
        var hashAlg = key.KeySize switch
        {
            256 => HashAlgorithmName.SHA256,
            384 => HashAlgorithmName.SHA384,
            521 => HashAlgorithmName.SHA512,
            _ => throw new NotSupportedException($"The algorithm '{key.SignatureAlgorithm}' is not supported."),
        };
        var securityAlgo = key switch
        {
            ECDsa when key.KeySize == 256 => SecurityAlgorithms.EcdsaSha256,
            ECDsa when key.KeySize == 384 => SecurityAlgorithms.EcdsaSha384,
            ECDsa when key.KeySize == 521 => SecurityAlgorithms.EcdsaSha512,
            RSA => SecurityAlgorithms.RsaSha256, // Default to RSA SHA256
            _ => throw new NotSupportedException($"The algorithm '{key.SignatureAlgorithm}' is not supported."),
        };
        return new Key(securityAlgo, jwk, hashAlg);
    }
}
