namespace OpenCertServer.Ca.Utils;

using System.Security.Cryptography;
using System.Text;

/// <summary>
/// Password hashes, used by the EST Basic authentication and the CLI that makes them: PBKDF2 with HMAC-SHA256, encoded as
/// <c>pbkdf2-sha256$&lt;iterations&gt;$&lt;salt base64&gt;$&lt;hash base64&gt;</c>. The server configuration
/// holds hashes only; the password itself exists on the client and in the operator's head.
/// </summary>
public static class PasswordHash
{
    /// <summary>The number of PBKDF2 rounds used when creating a hash (OWASP, 2023, for HMAC-SHA256).</summary>
    public const int DefaultIterations = 600_000;

    private const string Prefix = "pbkdf2-sha256";
    private const int SaltSize = 16;
    private const int HashSize = 32;

    /// <summary>Creates the encoded hash of <paramref name="password"/> with a fresh random salt.</summary>
    public static string Create(string password, int iterations = DefaultIterations)
    {
        ArgumentNullException.ThrowIfNull(password);
        ArgumentOutOfRangeException.ThrowIfLessThan(iterations, 1);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, HashSize);
        return $"{Prefix}${iterations}${Convert.ToBase64String(salt)}${Convert.ToBase64String(hash)}";
    }

    /// <summary>
    /// Whether <paramref name="password"/> is the password behind <paramref name="encodedHash"/>. A hash
    /// that cannot be parsed verifies nothing, in constant time as far as the comparison goes.
    /// </summary>
    public static bool Verify(string password, string? encodedHash)
    {
        if (password is null || encodedHash is null)
        {
            return false;
        }

        var parts = encodedHash.Split('$');
        if (parts.Length != 4 || parts[0] != Prefix || !int.TryParse(parts[1], out var iterations) || iterations < 1)
        {
            return false;
        }

        byte[] salt, expected;
        try
        {
            salt = Convert.FromBase64String(parts[2]);
            expected = Convert.FromBase64String(parts[3]);
        }
        catch (FormatException)
        {
            return false;
        }

        var actual = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }
}
