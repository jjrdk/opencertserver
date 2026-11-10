namespace OpenCertServer.Contrib.Intune;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

/// <summary>
/// The signed client assertion for the certificate credential of an Entra app
/// registration (RFC 7523, as Entra expects it): RS256 over a JWT whose header carries
/// the certificate thumbprint (<c>x5t</c>, and <c>x5t#S256</c> for newer tenants) and
/// whose claims name the app as issuer and subject and the token endpoint as audience,
/// valid for ten minutes. Built by hand - the package has no JWT library and needs none.
/// </summary>
internal sealed class ClientAssertion : IDisposable
{
    private readonly RSA _key;
    private readonly string _x5t;
    private readonly string _x5tS256;

    private ClientAssertion(RSA key, X509Certificate2 certificate)
    {
        _key = key;
        _x5t = Base64Url(certificate.GetCertHash(HashAlgorithmName.SHA1));
        _x5tS256 = Base64Url(certificate.GetCertHash(HashAlgorithmName.SHA256));
    }

    public static ClientAssertion Load(IntuneOptions options)
    {
        if (string.IsNullOrEmpty(options.ClientCertificateFile) || string.IsNullOrEmpty(options.ClientCertificateKeyFile))
        {
            throw new InvalidOperationException("Scep:Intune:ClientCertificateFile needs ClientCertificateKeyFile beside it.");
        }

        using var certificate = X509Certificate2.CreateFromPemFile(options.ClientCertificateFile, options.ClientCertificateKeyFile);
        var key = RSA.Create();
        key.ImportFromPem(File.ReadAllText(options.ClientCertificateKeyFile));
        return new ClientAssertion(key, certificate);
    }

    public string Create(string clientId, Uri audience, DateTimeOffset now)
    {
        var header = JsonSerializer.Serialize(
            new AssertionHeader("RS256", "JWT", _x5t, _x5tS256), IntuneJsonContext.Default.AssertionHeader);
        var claims = JsonSerializer.Serialize(
            new AssertionClaims(
                audience.ToString(),
                clientId,
                clientId,
                Guid.NewGuid().ToString(),
                now.AddMinutes(-1).ToUnixTimeSeconds(),
                now.AddMinutes(10).ToUnixTimeSeconds()),
            IntuneJsonContext.Default.AssertionClaims);
        var signingInput = Base64Url(Encoding.UTF8.GetBytes(header)) + "." + Base64Url(Encoding.UTF8.GetBytes(claims));
        var signature = _key.SignData(Encoding.UTF8.GetBytes(signingInput), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return signingInput + "." + Base64Url(signature);
    }

    private static string Base64Url(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public void Dispose() => _key.Dispose();
}
