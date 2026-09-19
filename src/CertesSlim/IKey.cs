namespace CertesSlim;

using System.Security.Cryptography;
using System.Text;
using CertesSlim.Json;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Represents key parameters used for signing.
/// </summary>
public interface IKey
{
    /// <summary>
    /// Gets the algorithm.
    /// </summary>
    /// <value>
    /// The algorithm.
    /// </value>
    string Algorithm { get; }

    /// <summary>
    /// Gets the hash algorithm.
    /// </summary>
    HashAlgorithmName HashAlgorithm { get; }

    /// <summary>
    /// Gets the security key.
    /// </summary>
    SecurityKey SecurityKey { get; }

    /// <summary>
    /// Gets the json web key.
    /// </summary>
    /// <value>
    /// The json web key.
    /// </value>
    JsonWebKey JsonWebKey { get; }

    /// <summary>
    /// Exports to PEM.
    /// </summary>
    /// <returns>PEM encoded data.</returns>
    string ToPem();
}

/// <summary>
/// Helper methods for <see cref="IKey"/>.
/// </summary>
public static class ISignatureKeyExtensions
{
    /// <param name="key">The account key.</param>
    extension(IKey key)
    {
        /// <summary>
        /// Generates the thumbprint for the given account key.
        /// </summary>
        /// <returns>The thumbprint.</returns>
        internal byte[] GenerateThumbprint()
        {
            return key.JsonWebKey.ComputeJwkThumbprint();
        }

        /// <summary>
        /// Generates the base64 encoded thumbprint for the given account key.
        /// </summary>
        /// <returns>The thumbprint.</returns>
        public string Thumbprint()
        {
            var jwkThumbprint = key.GenerateThumbprint();
            return jwkThumbprint.ToBase64String();
        }

        /// <summary>
        /// Generates key authorization string.
        /// </summary>
        /// <param name="token">The challenge token.</param>
        /// <returns>The key authorization string.</returns>
        public string KeyAuthorization(string token)
        {
            var jwkThumbprintEncoded = key.Thumbprint();
            return $"{token}.{jwkThumbprintEncoded}";
        }

        /// <summary>
        /// Generates the value for DNS TXT record.
        /// </summary>
        /// <param name="token">The challenge token.</param>
        /// <returns>The DNS text value for dns-01 validation.</returns>
        public string DnsTxt(string token)
        {
            var keyAuthz = key.KeyAuthorization(token);
            var hashed = SHA256.HashData(Encoding.UTF8.GetBytes(keyAuthz));
            return hashed.ToBase64String();
        }
    }
}
