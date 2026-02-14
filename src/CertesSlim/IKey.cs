using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CertesSlim.Json;
using Microsoft.IdentityModel.Tokens;

namespace CertesSlim;

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
            var jwk = key.JsonWebKey;
            var json = JsonSerializer.Serialize(jwk, CertesSerializerContext.Default.JsonWebKey);
            var bytes = Encoding.UTF8.GetBytes(json);
            var hashed = SHA256.HashData(bytes);

            return hashed;
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

    //        /// <summary>
//        /// Generates the certificate for <see cref="ChallengeTypes.TlsAlpn01" /> validation.
//        /// </summary>
//        /// <param name="key">The key.</param>
//        /// <param name="token">The <see cref="ChallengeTypes.TlsAlpn01" /> token.</param>
//        /// <param name="subjectName">Name of the subject.</param>
//        /// <param name="certificateKey">The certificate key pair.</param>
//        /// <returns>The tls-alpn-01 certificate in PEM.</returns>
//        public static string TlsAlpnCertificate(this IKey key, string token, string subjectName, IKey certificateKey)
//        {
//            var keyAuthz = key.KeyAuthorization(token);
//            var hashed = DigestUtilities.CalculateDigest("SHA256", Encoding.UTF8.GetBytes(keyAuthz));
//
//            var (_, keyPair) = signatureAlgorithmProvider.GetKeyPair(certificateKey.ToDer());
//
//            var signatureFactory = new Asn1SignatureFactory(certificateKey.Algorithm.ToPkcsObjectId(), keyPair.Private, new SecureRandom());
//            var gen = new X509V3CertificateGenerator();
//            var certName = new X509Name($"CN={subjectName}");
//            var serialNo = BigInteger.ProbablePrime(120, new SecureRandom());
//
//            gen.SetSerialNumber(serialNo);
//            gen.SetSubjectDN(certName);
//            gen.SetIssuerDN(certName);
//            gen.SetNotBefore(DateTime.UtcNow);
//            gen.SetNotAfter(DateTime.UtcNow.AddDays(7));
//            gen.SetPublicKey(keyPair.Public);
//
//            // SAN for validation
//            var gns = new[] { new GeneralName(GeneralName.DnsName, subjectName) };
//            gen.AddExtension(X509Extensions.SubjectAlternativeName.Id, false, new GeneralNames(gns));
//
//            // ACME-TLS/1
//            gen.AddExtension(
//                acmeValidationV1Id,
//                true,
//                hashed);
//
//            var newCert = gen.Generate(signatureFactory);
//
//            using (var sr = new StringWriter())
//            {
//                var pemWriter = new PemWriter(sr);
//                pemWriter.WriteObject(newCert);
//                return sr.ToString();
//            }
//        }
}
