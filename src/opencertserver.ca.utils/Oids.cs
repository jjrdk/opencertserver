namespace OpenCertServer.Ca.Utils;

using System.Security.Cryptography;

public static class Oids
{
    // Symmetric encryption algorithms
    public const string Rc2Cbc = "1.2.840.113549.3.2";
    public const string Rc4 = "1.2.840.113549.3.4";
    public const string TripleDesCbc = "1.2.840.113549.3.7";
    public const string DesCbc = "1.3.14.3.2.7";
    public const string Aes128Cbc = "2.16.840.1.101.3.4.1.2";
    public const string Aes192Cbc = "2.16.840.1.101.3.4.1.22";
    public const string Aes256Cbc = "2.16.840.1.101.3.4.1.42";

    // Asymmetric encryption algorithms
    public const string Dsa = "1.2.840.10040.4.1";
    public const string Rsa = "1.2.840.113549.1.1.1";
    public const string RsaOaep = "1.2.840.113549.1.1.7";
    public const string RsaPss = "1.2.840.113549.1.1.10";
    public const string RsaPkcs1Md5 = "1.2.840.113549.1.1.4";
    public const string RsaPkcs1Sha1 = "1.2.840.113549.1.1.5";
    public const string RsaPkcs1Sha256 = "1.2.840.113549.1.1.11";
    public const string RsaPkcs1Sha384 = "1.2.840.113549.1.1.12";
    public const string RsaPkcs1Sha512 = "1.2.840.113549.1.1.13";
    public const string RsaPkcs1Sha3_256 = "2.16.840.1.101.3.4.3.14";
    public const string RsaPkcs1Sha3_384 = "2.16.840.1.101.3.4.3.15";
    public const string RsaPkcs1Sha3_512 = "2.16.840.1.101.3.4.3.16";
    public const string Esdh = "1.2.840.113549.1.9.16.3.5";
    public const string EcDiffieHellman = "1.3.132.1.12";
    public const string DiffieHellman = "1.2.840.10046.2.1";
    public const string DiffieHellmanPkcs3 = "1.2.840.113549.1.3.1";

    // Cryptographic Attribute Types
    public const string SigningTime = "1.2.840.113549.1.9.5";
    public const string ContentType = "1.2.840.113549.1.9.3";
    public const string DocumentDescription = "1.3.6.1.4.1.311.88.2.2";
    public const string MessageDigest = "1.2.840.113549.1.9.4";
    public const string CounterSigner = "1.2.840.113549.1.9.6";
    public const string SigningCertificate = "1.2.840.113549.1.9.16.2.12";
    public const string SigningCertificateV2 = "1.2.840.113549.1.9.16.2.47";
    public const string DocumentName = "1.3.6.1.4.1.311.88.2.1";
    public const string Pkcs9FriendlyName = "1.2.840.113549.1.9.20";
    public const string LocalKeyId = "1.2.840.113549.1.9.21";
    public const string EnrollCertTypeExtension = "1.3.6.1.4.1.311.20.2";
    public const string UserPrincipalName = "1.3.6.1.4.1.311.20.2.3";
    public const string CertificateTemplate = "1.3.6.1.4.1.311.21.7";
    public const string ApplicationCertPolicies = "1.3.6.1.4.1.311.21.10";
    public const string AuthorityInformationAccess = "1.3.6.1.5.5.7.1.1";
    public const string OcspEndpoint = "1.3.6.1.5.5.7.48.1";
    public const string CertificateAuthorityIssuers = "1.3.6.1.5.5.7.48.2";
    public const string Pkcs9ExtensionRequest = "1.2.840.113549.1.9.14";
    public const string MsPkcs12KeyProviderName = "1.3.6.1.4.1.311.17.1";
    public const string MsPkcs12MachineKeySet = "1.3.6.1.4.1.311.17.2";

    // Key wrap algorithms
    public const string CmsRc2Wrap = "1.2.840.113549.1.9.16.3.7";
    public const string Cms3DesWrap = "1.2.840.113549.1.9.16.3.6";

    // PKCS7 Content Types.
    public const string Pkcs7Data = "1.2.840.113549.1.7.1";
    public const string Pkcs7Signed = "1.2.840.113549.1.7.2";
    public const string Pkcs7Enveloped = "1.2.840.113549.1.7.3";
    public const string Pkcs7SignedEnveloped = "1.2.840.113549.1.7.4";
    public const string Pkcs7Hashed = "1.2.840.113549.1.7.5";
    public const string Pkcs7Encrypted = "1.2.840.113549.1.7.6";

    // Hash algorithms
    public const string Md5 = "1.2.840.113549.2.5";
    public const string Sha1 = "1.3.14.3.2.26";
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    public const string Sha384 = "2.16.840.1.101.3.4.2.2";
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";
    public const string Sha3_256 = "2.16.840.1.101.3.4.2.8";
    public const string Sha3_384 = "2.16.840.1.101.3.4.2.9";
    public const string Sha3_512 = "2.16.840.1.101.3.4.2.10";
    public const string Shake128 = "2.16.840.1.101.3.4.2.11";
    public const string Shake256 = "2.16.840.1.101.3.4.2.12";

    // DSA CMS uses the combined signature+digest OID
    public const string DsaWithSha1 = "1.2.840.10040.4.3";
    public const string DsaWithSha256 = "2.16.840.1.101.3.4.3.2";
    public const string DsaWithSha384 = "2.16.840.1.101.3.4.3.3";
    public const string DsaWithSha512 = "2.16.840.1.101.3.4.3.4";

    // ECDSA CMS uses the combined signature+digest OID
    // https://tools.ietf.org/html/rfc5753#section-2.1.1
    public const string EcPrimeField = "1.2.840.10045.1.1";
    public const string EcChar2Field = "1.2.840.10045.1.2";
    public const string EcChar2TrinomialBasis = "1.2.840.10045.1.2.3.2";
    public const string EcChar2PentanomialBasis = "1.2.840.10045.1.2.3.3";
    public const string EcPublicKey = "1.2.840.10045.2.1";
    public const string ECDsaWithSha1 = "1.2.840.10045.4.1";
    public const string ECDsaWithSha256 = "1.2.840.10045.4.3.2";
    public const string ECDsaWithSha384 = "1.2.840.10045.4.3.3";
    public const string ECDsaWithSha512 = "1.2.840.10045.4.3.4";

    public const string ECDsaWithSha3_256 = "2.16.840.1.101.3.4.3.10";
    public const string ECDsaWithSha3_384 = "2.16.840.1.101.3.4.3.11";
    public const string ECDsaWithSha3_512 = "2.16.840.1.101.3.4.3.12";

    public const string MLDsa44 = "2.16.840.1.101.3.4.3.17";
    public const string MLDsa65 = "2.16.840.1.101.3.4.3.18";
    public const string MLDsa87 = "2.16.840.1.101.3.4.3.19";
    public const string MLDsa44PreHashSha512 = "2.16.840.1.101.3.4.3.32";
    public const string MLDsa65PreHashSha512 = "2.16.840.1.101.3.4.3.33";
    public const string MLDsa87PreHashSha512 = "2.16.840.1.101.3.4.3.34";

    public const string SlhDsaSha2_128s = "2.16.840.1.101.3.4.3.20";
    public const string SlhDsaSha2_128f = "2.16.840.1.101.3.4.3.21";
    public const string SlhDsaSha2_192s = "2.16.840.1.101.3.4.3.22";
    public const string SlhDsaSha2_192f = "2.16.840.1.101.3.4.3.23";
    public const string SlhDsaSha2_256s = "2.16.840.1.101.3.4.3.24";
    public const string SlhDsaSha2_256f = "2.16.840.1.101.3.4.3.25";
    public const string SlhDsaShake128s = "2.16.840.1.101.3.4.3.26";
    public const string SlhDsaShake128f = "2.16.840.1.101.3.4.3.27";
    public const string SlhDsaShake192s = "2.16.840.1.101.3.4.3.28";
    public const string SlhDsaShake192f = "2.16.840.1.101.3.4.3.29";
    public const string SlhDsaShake256s = "2.16.840.1.101.3.4.3.30";
    public const string SlhDsaShake256f = "2.16.840.1.101.3.4.3.31";
    public const string SlhDsaSha2_128sPreHashSha256 = "2.16.840.1.101.3.4.3.35";
    public const string SlhDsaSha2_128fPreHashSha256 = "2.16.840.1.101.3.4.3.36";
    public const string SlhDsaSha2_192sPreHashSha512 = "2.16.840.1.101.3.4.3.37";
    public const string SlhDsaSha2_192fPreHashSha512 = "2.16.840.1.101.3.4.3.38";
    public const string SlhDsaSha2_256sPreHashSha512 = "2.16.840.1.101.3.4.3.39";
    public const string SlhDsaSha2_256fPreHashSha512 = "2.16.840.1.101.3.4.3.40";
    public const string SlhDsaShake128sPreHashShake128 = "2.16.840.1.101.3.4.3.41";
    public const string SlhDsaShake128fPreHashShake128 = "2.16.840.1.101.3.4.3.42";
    public const string SlhDsaShake192sPreHashShake256 = "2.16.840.1.101.3.4.3.43";
    public const string SlhDsaShake192fPreHashShake256 = "2.16.840.1.101.3.4.3.44";
    public const string SlhDsaShake256sPreHashShake256 = "2.16.840.1.101.3.4.3.45";
    public const string SlhDsaShake256fPreHashShake256 = "2.16.840.1.101.3.4.3.46";

    public const string Mgf1 = "1.2.840.113549.1.1.8";
    public const string PSpecified = "1.2.840.113549.1.1.9";

    public const string MLDsa44WithRSA2048PssPreHashSha256 = "2.16.840.1.114027.80.9.1.20";
    public const string MLDsa44WithRSA2048Pkcs15PreHashSha256 = "2.16.840.1.114027.80.9.1.21";
    public const string MLDsa44WithEd25519PreHashSha512 = "2.16.840.1.114027.80.9.1.22";
    public const string MLDsa44WithECDsaP256PreHashSha256 = "2.16.840.1.114027.80.9.1.23";
    public const string MLDsa65WithRSA3072PssPreHashSha512 = "2.16.840.1.114027.80.9.1.24";
    public const string MLDsa65WithRSA3072Pkcs15PreHashSha512 = "2.16.840.1.114027.80.9.1.25";
    public const string MLDsa65WithRSA4096PssPreHashSha512 = "2.16.840.1.114027.80.9.1.26";
    public const string MLDsa65WithRSA4096Pkcs15PreHashSha512 = "2.16.840.1.114027.80.9.1.27";
    public const string MLDsa65WithECDsaP256PreHashSha512 = "2.16.840.1.114027.80.9.1.28";
    public const string MLDsa65WithECDsaP384PreHashSha512 = "2.16.840.1.114027.80.9.1.29";
    public const string MLDsa65WithECDsaBrainpoolP256r1PreHashSha512 = "2.16.840.1.114027.80.9.1.30";
    public const string MLDsa65WithEd25519PreHashSha512 = "2.16.840.1.114027.80.9.1.31";
    public const string MLDsa87WithECDsaP384PreHashSha512 = "2.16.840.1.114027.80.9.1.32";
    public const string MLDsa87WithECDsaBrainpoolP384r1PreHashSha512 = "2.16.840.1.114027.80.9.1.33";
    public const string MLDsa87WithEd448PreHashShake256_512 = "2.16.840.1.114027.80.9.1.34";
    public const string MLDsa87WithRSA3072PssPreHashSha512 = "2.16.840.1.114027.80.9.1.35";
    public const string MLDsa87WithRSA4096PssPreHashSha512 = "2.16.840.1.114027.80.9.1.36";
    public const string MLDsa87WithECDsaP521PreHashSha512 = "2.16.840.1.114027.80.9.1.37";

    // PKCS#7
    public const string NoSignature = "1.3.6.1.5.5.7.6.2";

    // X500 Names - T-REC X.520-201910
    public const string KnowledgeInformation = "2.5.4.2"; // 6.1.1 - id-at-knowledgeInformation
    public const string CommonName = "2.5.4.3"; // 6.2.2 - id-at-commonName
    public const string Surname = "2.5.4.4"; // 6.2.3 - id-at-surname
    public const string SerialNumber = "2.5.4.5"; // 6.2.9 - id-at-serialNumber
    public const string CountryOrRegionName = "2.5.4.6"; // 6.3.1 - id-at-countryName
    public const string LocalityName = "2.5.4.7"; // 6.3.4 - id-at-localityName
    public const string StateOrProvinceName = "2.5.4.8"; // 6.3.5 - id-at-stateOrProvinceName
    public const string StreetAddress = "2.5.4.9"; // 6.3.6 - id-at-streetAddress
    public const string Organization = "2.5.4.10"; // 6.4.1 - id-at-organizationName
    public const string OrganizationalUnit = "2.5.4.11"; // 6.4.2 - id-at-organizationalUnitName
    public const string Title = "2.5.4.12"; // 6.4.3 - id-at-title
    public const string Description = "2.5.4.13"; // 6.5.1 - id-at-description
    public const string BusinessCategory = "2.5.4.15"; // 6.5.4 - id-at-businessCategory
    public const string PostalCode = "2.5.4.17"; // 6.6.2 - id-at-postalCode
    public const string PostOfficeBox = "2.5.4.18"; // 6.6.3 - id-at-postOfficeBox
    public const string PhysicalDeliveryOfficeName = "2.5.4.19"; // 6.6.4 - id-at-physicalDeliveryOfficeName
    public const string TelephoneNumber = "2.5.4.20"; // 6.7.1 - id-at-telephoneNumber
    public const string X121Address = "2.5.4.24"; // 6.7.5 - id-at-x121Address
    public const string InternationalISDNNumber = "2.5.4.25"; // 6.7.6 - id-at-internationalISDNNumber
    public const string DestinationIndicator = "2.5.4.27"; // 6.7.8 - id-at-destinationIndicator
    public const string Name = "2.5.4.41"; // 6.2.1 - id-at-name
    public const string GivenName = "2.5.4.42"; // 6.2.4 - id-at-givenName
    public const string Initials = "2.5.4.43"; // 6.2.5 - id-at-initials
    public const string GenerationQualifier = "2.5.4.44"; // 6.2.6 - id-at-generationQualifier
    public const string DnQualifier = "2.5.4.46"; // 6.2.8 - id-at-dnQualifier
    public const string HouseIdentifier = "2.5.4.51"; // 6.3.7 - id-at-houseIdentifier
    public const string DmdName = "2.5.4.54"; // 6.11.1 - id-at-dmdName
    public const string Pseudonym = "2.5.4.65"; // 6.2.10 - id-at-pseudonym
    public const string UiiInUrn = "2.5.4.80"; // 6.13.3 - id-at-uiiInUrn
    public const string ContentUrl = "2.5.4.81"; // 6.13.4 - id-at-contentUrl
    public const string Uri = "2.5.4.83"; // 6.2.12 - id-at-uri
    public const string Urn = "2.5.4.86"; // 6.2.13 - id-at-urn
    public const string Url = "2.5.4.87"; // 6.2.14 - id-at-url
    public const string UrnC = "2.5.4.89"; // 6.12.4 - id-at-urnC
    public const string EpcInUrn = "2.5.4.94"; // 6.13.9 - id-at-epcInUrn
    public const string LdapUrl = "2.5.4.95"; // 6.13.10 - id-at-ldapUrl
    public const string OrganizationIdentifier = "2.5.4.97"; // 6.4.4 - id-at-organizationIdentifier
    public const string CountryOrRegionName3C = "2.5.4.98"; // 6.3.2 - id-at-countryCode3c
    public const string CountryOrRegionName3N = "2.5.4.99"; // 6.3.3 - id-at-countryCode3n
    public const string DnsName = "2.5.4.100"; // 6.2.15 - id-at-dnsName
    public const string IntEmail = "2.5.4.104"; // 6.2.16 - id-at-intEmail
    public const string JabberId = "2.5.4.105"; // 6.2.17 - id-at-jid

    // RFC 2985
    public const string EmailAddress = "1.2.840.113549.1.9.1"; //  B.3.5

    // Cert Extensions
    public const string BasicConstraints = "2.5.29.10";
    public const string SubjectKeyIdentifier = "2.5.29.14";
    public const string KeyUsage = "2.5.29.15";
    public const string SubjectAltName = "2.5.29.17";
    public const string IssuerAltName = "2.5.29.18";
    public const string BasicConstraints2 = "2.5.29.19";
    public const string CrlNumber = "2.5.29.20";
    public const string CrlReasons = "2.5.29.21";
    public const string CrlDistributionPoints = "2.5.29.31";
    public const string CertPolicies = "2.5.29.32";
    public const string AnyCertPolicy = "2.5.29.32.0";
    public const string CertPolicyMappings = "2.5.29.33";
    public const string AuthorityKeyIdentifier = "2.5.29.35";
    public const string CertPolicyConstraints = "2.5.29.36";
    public const string EnhancedKeyUsage = "2.5.29.37";
    public const string InhibitAnyPolicyExtension = "2.5.29.54";

    // RFC3161 Timestamping
    public const string TstInfo = "1.2.840.113549.1.9.16.1.4";
    public const string TimeStampingPurpose = "1.3.6.1.5.5.7.3.8";

    // PKCS#12
    private const string Pkcs12Prefix = "1.2.840.113549.1.12.";
    private const string Pkcs12PbePrefix = Pkcs12Prefix + "1.";
    public const string Pkcs12PbeWithShaAnd3Key3Des = Pkcs12PbePrefix + "3";
    public const string Pkcs12PbeWithShaAnd2Key3Des = Pkcs12PbePrefix + "4";
    public const string Pkcs12PbeWithShaAnd128BitRC2 = Pkcs12PbePrefix + "5";
    public const string Pkcs12PbeWithShaAnd40BitRC2 = Pkcs12PbePrefix + "6";
    private const string Pkcs12BagTypesPrefix = Pkcs12Prefix + "10.1.";
    public const string Pkcs12KeyBag = Pkcs12BagTypesPrefix + "1";
    public const string Pkcs12ShroudedKeyBag = Pkcs12BagTypesPrefix + "2";
    public const string Pkcs12CertBag = Pkcs12BagTypesPrefix + "3";
    public const string Pkcs12CrlBag = Pkcs12BagTypesPrefix + "4";
    public const string Pkcs12SecretBag = Pkcs12BagTypesPrefix + "5";
    public const string Pkcs12SafeContentsBag = Pkcs12BagTypesPrefix + "6";
    public const string Pkcs12X509CertBagType = "1.2.840.113549.1.9.22.1";
    public const string Pkcs12SdsiCertBagType = "1.2.840.113549.1.9.22.2";

    // PKCS#5
    private const string Pkcs5Prefix = "1.2.840.113549.1.5.";
    public const string PbeWithMD5AndDESCBC = Pkcs5Prefix + "3";
    public const string PbeWithMD5AndRC2CBC = Pkcs5Prefix + "6";
    public const string PbeWithSha1AndDESCBC = Pkcs5Prefix + "10";
    public const string PbeWithSha1AndRC2CBC = Pkcs5Prefix + "11";
    public const string Pbkdf2 = Pkcs5Prefix + "12";
    public const string PasswordBasedEncryptionScheme2 = Pkcs5Prefix + "13";

    private const string RsaDsiDigestAlgorithmPrefix = "1.2.840.113549.2.";
    public const string HmacWithSha1 = RsaDsiDigestAlgorithmPrefix + "7";
    public const string HmacWithSha256 = RsaDsiDigestAlgorithmPrefix + "9";
    public const string HmacWithSha384 = RsaDsiDigestAlgorithmPrefix + "10";
    public const string HmacWithSha512 = RsaDsiDigestAlgorithmPrefix + "11";

    // Elliptic Curve curve identifiers
    public const string secp256r1 = "1.2.840.10045.3.1.7";
    public const string secp384r1 = "1.3.132.0.34";
    public const string secp521r1 = "1.3.132.0.35";

    public const string brainpoolP256r1 = "1.3.36.3.3.2.8.1.1.7";
    public const string brainpoolP384r1 = "1.3.36.3.3.2.8.1.1.11";

    // LDAP
    public const string DomainComponent = "0.9.2342.19200300.100.1.25";

    // ML-KEM
    // id-alg-ml-kem-512
    public const string MlKem512 = "2.16.840.1.101.3.4.4.1";

    // id-alg-ml-kem-768
    public const string MlKem768 = "2.16.840.1.101.3.4.4.2";

    // id-alg-ml-kem-1024
    public const string MlKem1024 = "2.16.840.1.101.3.4.4.3";

    public static Oid RsaOid => field ??= Rsa.InitializeOid();
    public static Oid EcPublicKeyOid => field ??= EcPublicKey.InitializeOid();
    public static Oid TripleDesCbcOid => field ??= TripleDesCbc.InitializeOid();
    public static Oid Aes256CbcOid => field ??= Aes256Cbc.InitializeOid();
    public static Oid secp256r1Oid => field ??= new Oid(secp256r1, nameof(ECCurve.NamedCurves.nistP256));
    public static Oid secp384r1Oid => field ??= new Oid(secp384r1, nameof(ECCurve.NamedCurves.nistP384));
    public static Oid secp521r1Oid => field ??= new Oid(secp521r1, nameof(ECCurve.NamedCurves.nistP521));
    public static Oid Sha256Oid => field ??= Sha256.InitializeOid();

    public static Oid Pkcs7DataOid => field ??= Pkcs7Data.InitializeOid();
    public static Oid ContentTypeOid => field ??= ContentType.InitializeOid();
    public static Oid DocumentDescriptionOid => field ??= DocumentDescription.InitializeOid();
    public static Oid DocumentNameOid => field ??= DocumentName.InitializeOid();
    public static Oid LocalKeyIdOid => field ??= LocalKeyId.InitializeOid();
    public static Oid MessageDigestOid => field ??= MessageDigest.InitializeOid();
    public static Oid SigningTimeOid => field ??= SigningTime.InitializeOid();
    public static Oid Pkcs9ExtensionRequestOid => field ??= Pkcs9ExtensionRequest.InitializeOid();

    public static Oid BasicConstraints2Oid => field ??= BasicConstraints2.InitializeOid();
    public static Oid EnhancedKeyUsageOid => field ??= EnhancedKeyUsage.InitializeOid();
    public static Oid KeyUsageOid => field ??= KeyUsage.InitializeOid();
    public static Oid AuthorityKeyIdentifierOid => field ??= AuthorityKeyIdentifier.InitializeOid();
    public static Oid SubjectKeyIdentifierOid => field ??= SubjectKeyIdentifier.InitializeOid();
    public static Oid SubjectAltNameOid => field ??= SubjectAltName.InitializeOid();
    public static Oid AuthorityInformationAccessOid => field ??= AuthorityInformationAccess.InitializeOid();
    public static Oid CrlNumberOid => field ??= CrlNumber.InitializeOid();
    public static Oid CrlDistributionPointsOid => field ??= CrlDistributionPoints.InitializeOid();

    public static Oid CommonNameOid => field ??= CommonName.InitializeOid();
    public static Oid CountryOrRegionNameOid => field ??= CountryOrRegionName.InitializeOid();
    public static Oid LocalityNameOid => field ??= LocalityName.InitializeOid();
    public static Oid StateOrProvinceNameOid => field ??= StateOrProvinceName.InitializeOid();
    public static Oid OrganizationOid => field ??= Organization.InitializeOid();
    public static Oid OrganizationalUnitOid => field ??= OrganizationalUnit.InitializeOid();
    public static Oid EmailAddressOid => field ??= EmailAddress.InitializeOid();

    public static string GetSignatureAlgorithmOid(HashAlgorithmName hashAlgorithm, AsymmetricAlgorithm publicKey)
    {
        return (hashAlgorithm.Name, publicKey) switch
        {
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
