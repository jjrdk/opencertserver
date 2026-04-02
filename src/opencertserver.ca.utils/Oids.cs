namespace OpenCertServer.Ca.Utils;

using System.Security.Cryptography;

/// <summary>
/// Provides object identifier (OID) constants and friendly names used across cryptographic and X.509 operations.
/// </summary>
public static class Oids
{
    // Symmetric encryption algorithms
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Rc2Cbc = "1.2.840.113549.3.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Rc2CbcFriendlyName = "rc2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Rc4 = "1.2.840.113549.3.4";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Rc4FriendlyName = "rc4";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string TripleDesCbc = "1.2.840.113549.3.7";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string TripleDesCbcFriendlyName = "3des";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DesCbc = "1.3.14.3.2.7";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DesCbcFriendlyName = "des";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Aes128CbcFriendlyName = "aes128";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Aes192CbcFriendlyName = "aes192";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Aes256CbcFriendlyName = "aes256";

    // Asymmetric encryption algorithms
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Dsa = "1.2.840.10040.4.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DsaFriendlyName = "DSA";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Rsa = "1.2.840.113549.1.1.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaFriendlyName = "RSA";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaOaep = "1.2.840.113549.1.1.7";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaOaepFriendlyName = "RSAES_OAEP";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPss = "1.2.840.113549.1.1.10";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPssFriendlyName = "RSASSA-PSS";
//    public const string RsaPkcs1Md5 = "1.2.840.113549.1.1.4";
//    public const string RsaPkcs1Sha1 = "1.2.840.113549.1.1.5";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha256 = "1.2.840.113549.1.1.11";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha256FriendlyName = "sha256RSA";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha384 = "1.2.840.113549.1.1.12";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha384FriendlyName = "sha384RSA";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha512 = "1.2.840.113549.1.1.13";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha512FriendlyName = "sha512RSA";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha3_256 = "2.16.840.1.101.3.4.3.14";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha3_256FriendlyName = "id-rsassa-pkcs1-v1-5-with-sha3-256";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha3_384 = "2.16.840.1.101.3.4.3.15";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha3_384FriendlyName = "id-rsassa-pkcs1-v1-5-with-sha3-384";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha3_512 = "2.16.840.1.101.3.4.3.16";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string RsaPkcs1Sha3_512FriendlyName = "id-rsassa-pkcs1-v1-5-with-sha3-512";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Esdh = "1.2.840.113549.1.9.16.3.5";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EsdhFriendlyName = "ESDH";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcDiffieHellman = "1.3.132.1.12";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcDiffieHellmanFriendlyName = "ecdh";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DiffieHellman = "1.2.840.10046.2.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DiffieHellmanFriendlyName = "DH";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DiffieHellmanPkcs3 = "1.2.840.113549.1.3.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DiffieHellmanPkcs3FriendlyName = "DH";

    // Cryptographic Attribute Types
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SigningTime = "1.2.840.113549.1.9.5";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SigningTimeFriendlyName = "signingTime";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ContentType = "1.2.840.113549.1.9.3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ContentTypeFriendlyName = "contentType";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DocumentDescription = "1.3.6.1.4.1.311.88.2.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DocumentDescriptionFriendlyName = "Document Description";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MessageDigest = "1.2.840.113549.1.9.4";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MessageDigestFriendlyName = "messageDigest";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CounterSigner = "1.2.840.113549.1.9.6";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CounterSignerFriendlyName = "countersignature";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ChallengePassword = "1.2.840.113549.1.9.7";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ChallengePasswordFriendlyName = "challengePassword";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SigningCertificateFriendlyName = "signing-certificate";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SigningCertificateV2FriendlyName = "id-aa-signingCertificateV2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DocumentName = "1.3.6.1.4.1.311.88.2.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DocumentNameFriendlyName = "Document Name";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs9FriendlyName = "1.2.840.113549.1.9.20";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string LocalKeyId = "1.2.840.113549.1.9.21";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string LocalKeyIdFriendlyName = "localKeyID";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EnrollCertTypeExtension = "1.3.6.1.4.1.311.20.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EnrollCertTypeExtensionFriendlyName = "Certificate Template Name";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string UserPrincipalName = "1.3.6.1.4.1.311.20.2.3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string UserPrincipalNameFriendlyName = "User Principal Name";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertificateTemplate = "1.3.6.1.4.1.311.21.7";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertificateTemplateFriendlyName = "Certificate Template";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ApplicationCertPolicies = "1.3.6.1.4.1.311.21.10";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ApplicationCertPoliciesFriendlyName = "Application Policies";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string AuthorityInformationAccess = "1.3.6.1.5.5.7.1.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string AuthorityInformationAccessFriendlyName = "Authority Information Access";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string OcspEndpoint = "1.3.6.1.5.5.7.48.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string OcspEndpointFriendlyName = "id-ad-ocsp";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string OcspBasicResponse = "1.3.6.1.5.5.7.48.1.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string OcspBasicResponseFriendlyName = "id-pkix-ocsp-basic";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string OcspNonce = "1.3.6.1.5.5.7.48.1.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string OcspNonceFriendlyName = "id-pkix-ocsp-nonce";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertificateAuthorityIssuers = "1.3.6.1.5.5.7.48.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertificateAuthorityIssuersFriendlyName = "caIssuers";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs9ExtensionRequest = "1.2.840.113549.1.9.14";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs9ExtensionRequestFriendlyName = "id-ExtensionReq";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs9ExtensionRequestTemplate = "1.2.840.113549.1.9.62";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs9ExtensionRequestTemplateFriendlyName = "id-aa-extensionReqTemplate";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MsPkcs12KeyProviderName = "1.3.6.1.4.1.311.17.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MsPkcs12KeyProviderNameFriendlyName = "PKCS 12 Key Provider Name";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MsPkcs12MachineKeySet = "1.3.6.1.4.1.311.17.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MsPkcs12MachineKeySetFriendlyName = "Local Machine Keyset";

    // Key wrap algorithms
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CmsRc2Wrap = "1.2.840.113549.1.9.16.3.7";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CmsRc2WrapFriendlyName = "CMSRC2wrap";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Cms3DesWrap = "1.2.840.113549.1.9.16.3.6";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Cms3DesWrapFriendlyName = "CMS3DESwrap";

    // PKCS7 Content Types.
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7Data = "1.2.840.113549.1.7.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7DataFriendlyName = "pkcs7-data";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7Signed = "1.2.840.113549.1.7.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7SignedFriendlyName = "signedData";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7Enveloped = "1.2.840.113549.1.7.3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7EnvelopedFriendlyName = "envelopedData";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7SignedEnveloped = "1.2.840.113549.1.7.4";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7SignedEnvelopedFriendlyName = "signedAndEnvelopedData";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7Hashed = "1.2.840.113549.1.7.5";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7HashedFriendlyName = "digestedData";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7Encrypted = "1.2.840.113549.1.7.6";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs7EncryptedFriendlyName = "encryptedData";

    // Hash algorithms
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Md5 = "1.2.840.113549.2.5";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Md5FriendlyName = "md5";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha1 = "1.3.14.3.2.26";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha1FriendlyName = "sha1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha256FriendlyName = "sha256";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha384 = "2.16.840.1.101.3.4.2.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha384FriendlyName = "sha384";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha512FriendlyName = "sha512";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha3_256 = "2.16.840.1.101.3.4.2.8";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha3_256FriendlyName = "sha3-256";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha3_384 = "2.16.840.1.101.3.4.2.9";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha3_384FriendlyName = "sha3-384";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha3_512 = "2.16.840.1.101.3.4.2.10";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Sha3_512FriendlyName = "sha3-512";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Shake128 = "2.16.840.1.101.3.4.2.11";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Shake128FriendlyName = "shake128";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Shake256 = "2.16.840.1.101.3.4.2.12";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Shake256FriendlyName = "shake256";

    // DSA CMS uses the combined signature+digest OID
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DsaWithSha1 = "1.2.840.10040.4.3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DsaWithSha1FriendlyName = "sha1DSA";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DsaWithSha256 = "2.16.840.1.101.3.4.3.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DsaWithSha256FriendlyName = "dsa-with-sha256";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DsaWithSha384 = "2.16.840.1.101.3.4.3.3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DsaWithSha384FriendlyName = "dsa-with-sha384";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DsaWithSha512 = "2.16.840.1.101.3.4.3.4";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DsaWithSha512FriendlyName = "dsa-with-sha512";

    // ECDSA CMS uses the combined signature+digest OID
    // https://tools.ietf.org/html/rfc5753#section-2.1.1
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcPrimeField = "1.2.840.10045.1.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcPrimeFieldFriendlyName = "prime-field";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcChar2Field = "1.2.840.10045.1.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcChar2FieldFriendlyName = "characteristic-two-field";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcChar2TrinomialBasis = "1.2.840.10045.1.2.3.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcChar2TrinomialBasisFriendlyName = "tpBasis";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcChar2PentanomialBasis = "1.2.840.10045.1.2.3.3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcChar2PentanomialBasisFriendlyName = "ppBasis";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcPublicKey = "1.2.840.10045.2.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EcPublicKeyFriendlyName = "ECC";
//    public const string ECDsaWithSha1 = "1.2.840.10045.4.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha256 = "1.2.840.10045.4.3.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha256FriendlyName = "sha256ECDSA";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha384 = "1.2.840.10045.4.3.3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha384FriendlyName = "sha384ECDSA";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha512 = "1.2.840.10045.4.3.4";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha512FriendlyName = "sha512ECDSA";

    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha3_256 = "2.16.840.1.101.3.4.3.10";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha3_256FriendlyName = "id-ecdsa-with-sha3-256";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha3_384 = "2.16.840.1.101.3.4.3.11";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha3_384FriendlyName = "id-ecdsa-with-sha3-384";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha3_512 = "2.16.840.1.101.3.4.3.12";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ECDsaWithSha3_512FriendlyName = "id-ecdsa-with-sha3-512";

    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa44 = "2.16.840.1.101.3.4.3.17";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa44FriendlyName = "id-ml-dsa-44";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa65 = "2.16.840.1.101.3.4.3.18";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa65FriendlyName = "id-ml-dsa-65";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa87 = "2.16.840.1.101.3.4.3.19";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa87FriendlyName = "id-ml-dsa-87";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa44PreHashSha512 = "2.16.840.1.101.3.4.3.32";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa65PreHashSha512 = "2.16.840.1.101.3.4.3.33";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa87PreHashSha512 = "2.16.840.1.101.3.4.3.34";

    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_128s = "2.16.840.1.101.3.4.3.20";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_128sFriendlyName = "SLH-DSA-SHA2-128s";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_128f = "2.16.840.1.101.3.4.3.21";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_128fFriendlyName = "SLH-DSA-SHA2-128f";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_192s = "2.16.840.1.101.3.4.3.22";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_192sFriendlyName = "SLH-DSA-SHA2-192s";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_192f = "2.16.840.1.101.3.4.3.23";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_192fFriendlyName = "SLH-DSA-SHA2-192f";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_256s = "2.16.840.1.101.3.4.3.24";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_256sFriendlyName = "SLH-DSA-SHA2-256s";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_256f = "2.16.840.1.101.3.4.3.25";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_256fFriendlyName = "SLH-DSA-SHA2-256f";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake128s = "2.16.840.1.101.3.4.3.26";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake128sFriendlyName = "SLH-DSA-SHAKE-128s";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake128f = "2.16.840.1.101.3.4.3.27";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake128fFriendlyName = "SLH-DSA-SHAKE-128f";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake192s = "2.16.840.1.101.3.4.3.28";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake192sFriendlyName = "SLH-DSA-SHAKE-192s";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake192f = "2.16.840.1.101.3.4.3.29";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake192fFriendlyName = "SLH-DSA-SHAKE-192f";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake256s = "2.16.840.1.101.3.4.3.30";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake256sFriendlyName = "SLH-DSA-SHAKE-256s";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake256f = "2.16.840.1.101.3.4.3.31";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake256fFriendlyName = "SLH-DSA-SHAKE-256f";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_128sPreHashSha256 = "2.16.840.1.101.3.4.3.35";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_128sPreHashSha256FriendlyName = "id-hash-slh-dsa-sha2-128s-with-sha256";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_128fPreHashSha256 = "2.16.840.1.101.3.4.3.36";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_128fPreHashSha256FriendlyName = "id-hash-slh-dsa-sha2-128f-with-sha256";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_192sPreHashSha512 = "2.16.840.1.101.3.4.3.37";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_192sPreHashSha512FriendlyName = "id-hash-slh-dsa-sha2-192s-with-sha512";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_192fPreHashSha512 = "2.16.840.1.101.3.4.3.38";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_192fPreHashSha512FriendlyName = "id-hash-slh-dsa-sha2-192f-with-sha512";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_256sPreHashSha512 = "2.16.840.1.101.3.4.3.39";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_256sPreHashSha512FriendlyName = "id-hash-slh-dsa-sha2-256s-with-sha512";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_256fPreHashSha512 = "2.16.840.1.101.3.4.3.40";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaSha2_256fPreHashSha512FriendlyName = "id-hash-slh-dsa-sha2-256f-with-sha512";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake128sPreHashShake128 = "2.16.840.1.101.3.4.3.41";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake128sPreHashShake128FriendlyName = "id-hash-slh-dsa-shake-128s-with-shake128";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake128fPreHashShake128 = "2.16.840.1.101.3.4.3.42";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake128fPreHashShake128FriendlyName = "id-hash-slh-dsa-shake-128f-with-shake128";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake192sPreHashShake256 = "2.16.840.1.101.3.4.3.43";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake192sPreHashShake256FriendlyName = "id-hash-slh-dsa-shake-192s-with-shake256";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake192fPreHashShake256 = "2.16.840.1.101.3.4.3.44";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake192fPreHashShake256FriendlyName = "id-hash-slh-dsa-shake-192f-with-shake256";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake256sPreHashShake256 = "2.16.840.1.101.3.4.3.45";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake256sPreHashShake256FriendlyName = "id-hash-slh-dsa-shake-256s-with-shake256";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake256fPreHashShake256 = "2.16.840.1.101.3.4.3.46";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SlhDsaShake256fPreHashShake256FriendlyName = "id-hash-slh-dsa-shake-256f-with-shake256";

    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Mgf1 = "1.2.840.113549.1.1.8";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Mgf1FriendlyName = "mgf1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PSpecified = "1.2.840.113549.1.1.9";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PSpecifiedFriendlyName = "id-pSpecified";

    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa44WithRSA2048PssPreHashSha256 = "2.16.840.1.114027.80.9.1.20";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa44WithRSA2048Pkcs15PreHashSha256 = "2.16.840.1.114027.80.9.1.21";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa44WithEd25519PreHashSha512 = "2.16.840.1.114027.80.9.1.22";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa44WithECDsaP256PreHashSha256 = "2.16.840.1.114027.80.9.1.23";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa65WithRSA3072PssPreHashSha512 = "2.16.840.1.114027.80.9.1.24";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa65WithRSA3072Pkcs15PreHashSha512 = "2.16.840.1.114027.80.9.1.25";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa65WithRSA4096PssPreHashSha512 = "2.16.840.1.114027.80.9.1.26";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa65WithRSA4096Pkcs15PreHashSha512 = "2.16.840.1.114027.80.9.1.27";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa65WithECDsaP256PreHashSha512 = "2.16.840.1.114027.80.9.1.28";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa65WithECDsaP384PreHashSha512 = "2.16.840.1.114027.80.9.1.29";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa65WithECDsaBrainpoolP256r1PreHashSha512 = "2.16.840.1.114027.80.9.1.30";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa65WithEd25519PreHashSha512 = "2.16.840.1.114027.80.9.1.31";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa87WithECDsaP384PreHashSha512 = "2.16.840.1.114027.80.9.1.32";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa87WithECDsaBrainpoolP384r1PreHashSha512 = "2.16.840.1.114027.80.9.1.33";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa87WithEd448PreHashShake256_512 = "2.16.840.1.114027.80.9.1.34";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa87WithRSA3072PssPreHashSha512 = "2.16.840.1.114027.80.9.1.35";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa87WithRSA4096PssPreHashSha512 = "2.16.840.1.114027.80.9.1.36";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MLDsa87WithECDsaP521PreHashSha512 = "2.16.840.1.114027.80.9.1.37";

    // PKCS#7
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string NoSignature = "1.3.6.1.5.5.7.6.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string NoSignatureFriendlyName = "NO_SIGN";

    // X500 Names - T-REC X.520-201910
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string KnowledgeInformation = "2.5.4.2"; // 6.1.1 - id-at-knowledgeInformation
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string KnowledgeInformationFriendlyName = "knowledgeInformation";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CommonName = "2.5.4.3"; // 6.2.2 - id-at-commonName
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CommonNameFriendlyName = "commonName";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Surname = "2.5.4.4"; // 6.2.3 - id-at-surname
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SurnameFriendlyName = "surname";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SerialNumber = "2.5.4.5"; // 6.2.9 - id-at-serialNumber
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SerialNumberFriendlyName = "serialNumber";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CountryOrRegionName = "2.5.4.6"; // 6.3.1 - id-at-countryName
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CountryOrRegionNameFriendlyName = "countryName";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string LocalityName = "2.5.4.7"; // 6.3.4 - id-at-localityName
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string LocalityNameFriendlyName = "localityName";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string StateOrProvinceName = "2.5.4.8"; // 6.3.5 - id-at-stateOrProvinceName
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string StateOrProvinceNameFriendlyName = "stateOrProvinceName";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string StreetAddress = "2.5.4.9"; // 6.3.6 - id-at-streetAddress
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string StreetAddressFriendlyName = "streetAddress";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Organization = "2.5.4.10"; // 6.4.1 - id-at-organizationName
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string OrganizationFriendlyName = "organizationName";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string OrganizationalUnit = "2.5.4.11"; // 6.4.2 - id-at-organizationalUnitName
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string OrganizationalUnitFriendlyName = "organizationalUnitName";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Title = "2.5.4.12"; // 6.4.3 - id-at-title
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string TitleFriendlyName = "title";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Description = "2.5.4.13"; // 6.5.1 - id-at-description
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DescriptionFriendlyName = "description";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string BusinessCategory = "2.5.4.15"; // 6.5.4 - id-at-businessCategory
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string BusinessCategoryFriendlyName = "businessCategory";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PostalCode = "2.5.4.17"; // 6.6.2 - id-at-postalCode
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PostalCodeFriendlyName = "postalCode";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PostOfficeBox = "2.5.4.18"; // 6.6.3 - id-at-postOfficeBox
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PostOfficeBoxFriendlyName = "postOfficeBox";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PhysicalDeliveryOfficeName = "2.5.4.19"; // 6.6.4 - id-at-physicalDeliveryOfficeName
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PhysicalDeliveryOfficeNameFriendlyName = "physicalDeliveryOfficeName";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string TelephoneNumber = "2.5.4.20"; // 6.7.1 - id-at-telephoneNumber
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string TelephoneNumberFriendlyName = "telephoneNumber";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string X121Address = "2.5.4.24"; // 6.7.5 - id-at-x121Address
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string X121AddressFriendlyName = "x121Address";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string InternationalISDNNumber = "2.5.4.25"; // 6.7.6 - id-at-internationalISDNNumber
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string InternationalISDNNumberFriendlyName = "internationalISDNNumber";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DestinationIndicator = "2.5.4.27"; // 6.7.8 - id-at-destinationIndicator
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DestinationIndicatorFriendlyName = "destinationIndicator";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Name = "2.5.4.41"; // 6.2.1 - id-at-name
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string NameFriendlyName = "name";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string GivenName = "2.5.4.42"; // 6.2.4 - id-at-givenName
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string GivenNameFriendlyName = "givenName";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Initials = "2.5.4.43"; // 6.2.5 - id-at-initials
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string InitialsFriendlyName = "initials";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string GenerationQualifier = "2.5.4.44"; // 6.2.6 - id-at-generationQualifier
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string GenerationQualifierFriendlyName = "generationQualifier";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DnQualifier = "2.5.4.46"; // 6.2.8 - id-at-dnQualifier
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DnQualifierFriendlyName = "dnQualifier";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string HouseIdentifier = "2.5.4.51"; // 6.3.7 - id-at-houseIdentifier
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string HouseIdentifierFriendlyName = "houseIdentifier";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DmdName = "2.5.4.54"; // 6.11.1 - id-at-dmdName
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DmdNameFriendlyName = "dmdName";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pseudonym = "2.5.4.65"; // 6.2.10 - id-at-pseudonym
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PseudonymFriendlyName = "pseudonym";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string UiiInUrn = "2.5.4.80"; // 6.13.3 - id-at-uiiInUrn
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string UiiInUrnFriendlyName = "uiiInUrn";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ContentUrl = "2.5.4.81"; // 6.13.4 - id-at-contentUrl
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ContentUrlFriendlyName = "contentUrl";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Uri = "2.5.4.83"; // 6.2.12 - id-at-uri
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string UriFriendlyName = "uri";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Urn = "2.5.4.86"; // 6.2.13 - id-at-urn
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string UrnFriendlyName = "urn";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Url = "2.5.4.87"; // 6.2.14 - id-at-url
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string UrlFriendlyName = "url";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string UrnC = "2.5.4.89"; // 6.12.4 - id-at-urnC
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string UrnCFriendlyName = "urnC";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EpcInUrn = "2.5.4.94"; // 6.13.9 - id-at-epcInUrn
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EpcInUrnFriendlyName = "epcInUrn";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string LdapUrl = "2.5.4.95"; // 6.13.10 - id-at-ldapUrl
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string LdapUrlFriendlyName = "ldapUrl";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string OrganizationIdentifier = "2.5.4.97"; // 6.4.4 - id-at-organizationIdentifier
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string OrganizationIdentifierFriendlyName = "organizationIdentifier";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CountryOrRegionName3C = "2.5.4.98"; // 6.3.2 - id-at-countryCode3c
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CountryOrRegionName3CFriendlyName = "id-at-countryCode3c";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CountryOrRegionName3N = "2.5.4.99"; // 6.3.3 - id-at-countryCode3n
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CountryOrRegionName3NFriendlyName = "id-at-countryCode3n";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DnsName = "2.5.4.100"; // 6.2.15 - id-at-dnsName
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DnsNameFriendlyName = "id-at-dnsName";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string IntEmail = "2.5.4.104"; // 6.2.16 - id-at-intEmail
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string IntEmailFriendlyName = "id-at-intEmail";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string JabberId = "2.5.4.105"; // 6.2.17 - id-at-jid
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string JabberIdFriendlyName = "id-at-jid";

    // RFC 2985
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EmailAddress = "1.2.840.113549.1.9.1"; //  B.3.5
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EmailAddressFriendlyName = "emailAddress";

    // Cert Extensions
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string BasicConstraints = "2.5.29.10";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string BasicConstraintsFriendlyName = "basicConstraints";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SubjectKeyIdentifier = "2.5.29.14";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SubjectKeyIdentifierFriendlyName = "X509v3 Subject Key Identifier";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string KeyUsage = "2.5.29.15";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string KeyUsageFriendlyName = "X509v3 Key Usage";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SubjectAltName = "2.5.29.17";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string SubjectAltNameFriendlyName = "X509v3 Subject Alternative Name";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string IssuerAltName = "2.5.29.18";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string IssuerAltNameFriendlyName = "issuerAltName";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string BasicConstraints2 = "2.5.29.19";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string BasicConstraints2FriendlyName = "X509v3 Basic Constraints";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CrlNumber = "2.5.29.20";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CrlNumberFriendlyName = "cRLNumber";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CrlReasons = "2.5.29.21";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CrlReasonsFriendlyName = "reasonCode";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CrlDistributionPoints = "2.5.29.31";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CrlDistributionPointsFriendlyName = "cRLDistributionPoints";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertPolicies = "2.5.29.32";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertPoliciesFriendlyName = "certificatePolicies";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string AnyCertPolicy = "2.5.29.32.0";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string AnyCertPolicyFriendlyName = "anyPolicy";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertPolicyMappings = "2.5.29.33";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertPolicyMappingsFriendlyName = "policyMappings";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string AuthorityKeyIdentifier = "2.5.29.35";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string AuthorityKeyIdentifierFriendlyName = "X509v3 Authority Key Identifier";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertPolicyConstraints = "2.5.29.36";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertPolicyConstraintsFriendlyName = "policyConstraints";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EnhancedKeyUsage = "2.5.29.37";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EnhancedKeyUsageFriendlyName = "X509v3 Extended Key Usage";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string InhibitAnyPolicyExtension = "2.5.29.54";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string InhibitAnyPolicyExtensionFriendlyName = "inhibitAnyPolicy";

    // Extension Purposes
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ServerAuthenticationPurpose = "1.3.6.1.5.5.7.3.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ServerAuthenticationPurposeFriendlyName = "id-kp-serverAuth";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ClientAuthenticationPurpose = "1.3.6.1.5.5.7.3.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string ClientAuthenticationPurposeFriendlyName = "id-kp-clientAuth";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CodeSigningPurpose = "1.3.6.1.5.5.7.3.3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CodeSigningPurposeFriendlyName = "id-kp-codeSigning";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EmailProtectionPurpose = "1.3.6.1.5.5.7.3.4";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string EmailProtectionPurposeFriendlyName = "id-kp-emailProtection";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertificateTrustListSigningPurpose = "1.3.6.1.4.1.311.10.3.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string CertificateTrustListSigningPurposeFriendlyName = "Certificate Trust List Signing";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MicrosoftServerGatedCryptoPurpose = "1.3.6.1.4.1.311.10.3.3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MicrosoftServerGatedCryptoPurposeFriendlyName = "Microsoft Server Gated Crypto";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MicrosoftEncryptingFileSystemPurpose = "1.3.6.1.4.1.311.10.3.4";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MicrosoftEncryptingFileSystemPurposeFriendlyName = "Encrypting File System";

    // RFC3161 Timestamping
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string TstInfo = "1.2.840.113549.1.9.16.1.4";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string TstInfoFriendlyName = "id-ct-TSTInfo";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string TimeStampingPurpose = "1.3.6.1.5.5.7.3.8";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string TimeStampingPurposeFriendlyName = "id-kp-timeStamping";

    // PKCS#12
    /// <summary>
    /// Represents the member.
    /// </summary>
    private const string Pkcs12Prefix = "1.2.840.113549.1.12.";
    /// <summary>
    /// Represents the member.
    /// </summary>
    private const string Pkcs12PbePrefix = Pkcs12Prefix + "1.";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12PbeWithShaAnd3Key3Des = Pkcs12PbePrefix + "3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12PbeWithShaAnd2Key3Des = Pkcs12PbePrefix + "4";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12PbeWithShaAnd128BitRC2 = Pkcs12PbePrefix + "5";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12PbeWithShaAnd40BitRC2 = Pkcs12PbePrefix + "6";
    /// <summary>
    /// Represents the member.
    /// </summary>
    private const string Pkcs12BagTypesPrefix = Pkcs12Prefix + "10.1.";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12KeyBag = Pkcs12BagTypesPrefix + "1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12ShroudedKeyBag = Pkcs12BagTypesPrefix + "2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12CertBag = Pkcs12BagTypesPrefix + "3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12CrlBag = Pkcs12BagTypesPrefix + "4";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12SecretBag = Pkcs12BagTypesPrefix + "5";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12SafeContentsBag = Pkcs12BagTypesPrefix + "6";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12X509CertBagType = "1.2.840.113549.1.9.22.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12X509CertBagTypeFriendlyName = "x509Certificate";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12SdsiCertBagType = "1.2.840.113549.1.9.22.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pkcs12SdsiCertBagTypeFriendlyName = "sdsiCertificate";

    // PKCS#5
    /// <summary>
    /// Represents the member.
    /// </summary>
    private const string Pkcs5Prefix = "1.2.840.113549.1.5.";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PbeWithMD5AndDESCBC = Pkcs5Prefix + "3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PbeWithMD5AndRC2CBC = Pkcs5Prefix + "6";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PbeWithSha1AndDESCBC = Pkcs5Prefix + "10";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PbeWithSha1AndRC2CBC = Pkcs5Prefix + "11";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string Pbkdf2 = Pkcs5Prefix + "12";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string PasswordBasedEncryptionScheme2 = Pkcs5Prefix + "13";

    /// <summary>
    /// Represents the member.
    /// </summary>
    private const string RsaDsiDigestAlgorithmPrefix = "1.2.840.113549.2.";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string HmacWithSha1 = RsaDsiDigestAlgorithmPrefix + "7";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string HmacWithSha256 = RsaDsiDigestAlgorithmPrefix + "9";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string HmacWithSha384 = RsaDsiDigestAlgorithmPrefix + "10";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string HmacWithSha512 = RsaDsiDigestAlgorithmPrefix + "11";

    // Elliptic Curve curve identifiers
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string secp256r1 = "1.2.840.10045.3.1.7";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string secp256r1FriendlyName = "ECDSA_P256";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string secp384r1 = "1.3.132.0.34";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string secp384r1FriendlyName = "ECDSA_P384";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string secp521r1 = "1.3.132.0.35";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string secp521r1FriendlyName = "ECDSA_P521";

    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string brainpoolP256r1 = "1.3.36.3.3.2.8.1.1.7";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string brainpoolP256r1FriendlyName = "brainpoolP256r1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string brainpoolP384r1 = "1.3.36.3.3.2.8.1.1.11";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string brainpoolP384r1FriendlyName = "brainpoolP384r1";

    // LDAP
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DomainComponent = "0.9.2342.19200300.100.1.25";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string DomainComponentFriendlyName = "DC";

    // ML-KEM
    // id-alg-ml-kem-512
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MlKem512 = "2.16.840.1.101.3.4.4.1";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MlKem512FriendlyName = "id-alg-ml-kem-512";

    // id-alg-ml-kem-768
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MlKem768 = "2.16.840.1.101.3.4.4.2";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MlKem768FriendlyName = "id-alg-ml-kem-768";

    // id-alg-ml-kem-1024
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MlKem1024 = "2.16.840.1.101.3.4.4.3";
    /// <summary>
    /// Represents the member.
    /// </summary>
    public const string MlKem1024FriendlyName = "id-alg-ml-kem-1024";

    /// <summary>
    /// Executes the GetSignatureAlgorithmOid operation.
    /// </summary>
    public static string GetSignatureAlgorithmOid(HashAlgorithmName hashAlgorithm, AsymmetricAlgorithm publicKey)
    {
        return (hashAlgorithm.Name, publicKey) switch
        {
//            (nameof(SHA256), RSA) => "1.2.840.113549.1.1.1", // rsassaPkcs
//            (nameof(SHA384), RSA) => "1.2.840.113549.1.1.1",
//            (nameof(SHA512), RSA) => "1.2.840.113549.1.1.1",
            (nameof(SHA256), RSA) => "1.2.840.113549.1.1.10", // rsassaPss
            (nameof(SHA384), RSA) => "1.2.840.113549.1.1.10",
            (nameof(SHA512), RSA) => "1.2.840.113549.1.1.10",
            (nameof(SHA1), RSA) => "1.2.840.113549.1.1.5", // sha1WithRSAEncryption
            (nameof(SHA256), ECDsa) => "1.2.840.10045.4.3.2", // ecdsa-with-SHA256
            (nameof(SHA384), ECDsa) => "1.2.840.10045.4.3.3",
            (nameof(SHA512), ECDsa) => "1.2.840.10045.4.3.4",
            (nameof(SHA1), ECDsa) => "1.2.840.10045.4.1", // ecdsa-with-SHA1
            _ => throw new CryptographicException(
                $"Unsupported signature algorithm: {hashAlgorithm.Name} with key type {publicKey.GetType()}.")
        };
    }
}
