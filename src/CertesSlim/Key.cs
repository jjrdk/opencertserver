namespace CertesSlim;

using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

internal class Key : IKey
{
    public Key(string algorithm, SecurityKey securityKey, HashAlgorithmName hashAlgorithm)
    {
        HashAlgorithm = hashAlgorithm;
        SecurityKey = securityKey;
        Algorithm = algorithm;
        JsonWebKey = JsonWebKeyConverter.ConvertFromSecurityKey(securityKey);
    }

    public string ToPem()
    {
        if (SecurityKey is X509SecurityKey x509Key)
        {
            return x509Key.Certificate.ExportCertificatePem();
        }

        return SecurityKey switch
        {
            RsaSecurityKey rsaKey => rsaKey.Rsa.ExportRSAPrivateKeyPem(),
            ECDsaSecurityKey ecdsaKey => ecdsaKey.ECDsa.ExportECPrivateKeyPem(),
            X509SecurityKey certKey => certKey.Certificate.ExportCertificatePem(),
            _ => throw new NotSupportedException()
        };
    }

    public string Algorithm { get; }
    public HashAlgorithmName HashAlgorithm { get; }
    public SecurityKey SecurityKey { get; }
    public JsonWebKey JsonWebKey { get; }
}
