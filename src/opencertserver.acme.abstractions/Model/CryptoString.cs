namespace OpenCertServer.Acme.Abstractions.Model;

using Microsoft.IdentityModel.Tokens;

/// <summary>
/// Provides a cryptographically secure random string generator, encoded in base64url format.
/// </summary>
public sealed class CryptoString
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CryptoString"/> class and generates a random value.
    /// </summary>
    /// <param name="byteCount">The number of random bytes to generate.</param>
    private CryptoString(int byteCount)
    {
        var bytes = new byte[byteCount];

        using (var cryptoRng = System.Security.Cryptography.RandomNumberGenerator.Create())
            cryptoRng.GetBytes(bytes);

        Value = Base64UrlEncoder.Encode(bytes);
    }

    /// <summary>
    /// Gets the generated base64url-encoded random string value.
    /// </summary>
    private string Value { get; }

    /// <summary>
    /// Generates a new cryptographically secure random string, encoded in base64url format.
    /// </summary>
    /// <param name="byteCount">The number of random bytes to use. Defaults to 48.</param>
    /// <returns>A new unique random string value.</returns>
    public static string NewValue(int byteCount = 48) => new CryptoString(byteCount).Value;
}
