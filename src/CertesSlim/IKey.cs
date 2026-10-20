namespace CertesSlim;

using System.Security.Cryptography;
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
