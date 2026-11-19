namespace OpenCertServer.Data.Serialization;

using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// Converts a <see cref="CaProfile"/> to and from the JSON <see cref="CaProfileDocument"/> stored in the
/// relational <c>CaProfiles</c> table. Cryptographic material is exported to PEM, so the document carries
/// no live key or certificate handle and can be reconstructed on read.
/// </summary>
internal static class CaProfileSerializer
{
    /// <summary>Serializes a profile to the JSON stored in the relational payload column.</summary>
    public static string Serialize(CaProfile profile) =>
        JsonSerializer.Serialize(ToDocument(profile), CaProfileSerializerContext.Default.CaProfileDocument);

    /// <summary>Reconstructs a profile from a JSON payload, importing its key and certificates from PEM.</summary>
    public static CaProfile Deserialize(string payload) =>
        FromDocument(JsonSerializer.Deserialize(payload, CaProfileSerializerContext.Default.CaProfileDocument)!);

    private static CaProfileDocument ToDocument(CaProfile profile)
    {
        var (privateKeyPem, privateKeyType) = ExportKey(profile.PrivateKey);
        var (ocspKeyPem, ocspKeyType) = profile.OcspSigningKey is null
            ? (null, null)
            : ExportKey(profile.OcspSigningKey);
        return new CaProfileDocument
        {
            Name = profile.Name,
            AllowPublicEnrollment = profile.AllowPublicEnrollment,
            PrivateKeyPem = privateKeyPem,
            PrivateKeyType = privateKeyType,
            CertificateChain = ToPem(profile.CertificateChain),
            PublishedCertificateChain = ToPem(profile.PublishedCertificateChain),
            TrustAnchors = ToPem(profile.TrustAnchors),
            AdditionalChainCertificates = ToPem(profile.AdditionalChainCertificates),
            CertificateValidity = profile.CertificateValidity,
            CrlNumber = profile.CrlNumber.ToString(CultureInfo.InvariantCulture),
            AllowedCsrExtensions = profile.AllowedCsrExtensions.ToList(),
            CertificatePolicies = profile.CertificatePolicies.ToList(),
            KeyUsage = profile.KeyUsage is null ? null : (long)profile.KeyUsage.Value,
            ExtendedKeyUsages = profile.ExtendedKeyUsages is null ? null : profile.ExtendedKeyUsages.ToList(),
            OcspFreshnessWindow = profile.OcspFreshnessWindow,
            OcspSigningCertificatePem = profile.OcspSigningCertificate?.ExportCertificatePem(),
            OcspSigningKeyPem = ocspKeyPem,
            OcspSigningKeyType = ocspKeyType,
        };
    }

    private static CaProfile FromDocument(CaProfileDocument document) => new()
    {
        Name = document.Name,
        AllowPublicEnrollment = document.AllowPublicEnrollment,
        PrivateKey = ImportKey(document.PrivateKeyPem, document.PrivateKeyType),
        CertificateChain = FromPem(document.CertificateChain),
        PublishedCertificateChain = FromPem(document.PublishedCertificateChain),
        TrustAnchors = FromPem(document.TrustAnchors),
        AdditionalChainCertificates = FromPem(document.AdditionalChainCertificates),
        CertificateValidity = document.CertificateValidity,
        CrlNumber = BigInteger.Parse(document.CrlNumber, CultureInfo.InvariantCulture),
        AllowedCsrExtensions = document.AllowedCsrExtensions,
        CertificatePolicies = document.CertificatePolicies,
        KeyUsage = document.KeyUsage is null ? null : (X509KeyUsageFlags)document.KeyUsage.Value,
        ExtendedKeyUsages = document.ExtendedKeyUsages,
        OcspFreshnessWindow = document.OcspFreshnessWindow,
        OcspSigningCertificate = document.OcspSigningCertificatePem is null
            ? null
            : X509Certificate2.CreateFromPem(document.OcspSigningCertificatePem),
        OcspSigningKey = document.OcspSigningKeyPem is null
            ? null
            : ImportKey(document.OcspSigningKeyPem, document.OcspSigningKeyType!),
    };

    private static List<string> ToPem(X509Certificate2Collection certificates) =>
        certificates.Select(certificate => certificate.ExportCertificatePem()).ToList();

    private static X509Certificate2Collection FromPem(IEnumerable<string> pems)
    {
        var collection = new X509Certificate2Collection();
        foreach (var pem in pems)
        {
            collection.Add(X509Certificate2.CreateFromPem(pem));
        }

        return collection;
    }

    private static (string Pem, string Type) ExportKey(AsymmetricAlgorithm key) => key switch
    {
        RSA rsa => (rsa.ExportPkcs8PrivateKeyPem(), nameof(RSA)),
        ECDsa ecdsa => (ecdsa.ExportECPrivateKeyPem(), nameof(ECDsa)),
        _ => throw new NotSupportedException($"Unsupported key type '{key.GetType().Name}'.")
    };

    private static AsymmetricAlgorithm ImportKey(string pem, string type) => type switch
    {
        nameof(RSA) => ImportRsa(pem),
        nameof(ECDsa) => ImportEcdsa(pem),
        _ => throw new NotSupportedException($"Unknown key type '{type}'.")
    };

    private static RSA ImportRsa(string pem)
    {
        var key = RSA.Create();
        key.ImportFromPem(pem);
        return key;
    }

    private static ECDsa ImportEcdsa(string pem)
    {
        var key = ECDsa.Create();
        key.ImportFromPem(pem);
        return key;
    }
}
