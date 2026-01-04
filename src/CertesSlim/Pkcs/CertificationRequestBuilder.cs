using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.IdentityModel.Tokens;

namespace CertesSlim.Pkcs;

/// <summary>
/// Represents a CSR builder.
/// </summary>
/// <seealso cref="ICertificationRequestBuilder" />
public class CertificationRequestBuilder : ICertificationRequestBuilder
{
    private static readonly string[] _validX509Names =
    [
        "CN", "C", "L", "ST", "O", "OU", "E"
    ];

    private Dictionary<string, string> _values = new();
//    private IKey? _keyPair;

    /// <summary>
    /// Gets the key.
    /// </summary>
    /// <value>
    /// The key.
    /// </value>
    public IKey Key { get; }

    /// <summary>
    /// Gets the subject alternative names.
    /// </summary>
    /// <value>
    /// The subject alternative names.
    /// </value>
    public IList<string> SubjectAlternativeNames
    {
        get { return field; }
        set
        {
            field = value ??
                throw new ArgumentNullException(nameof(SubjectAlternativeNames));
        }
    } = new List<string>();

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificationRequestBuilder"/> class.
    /// </summary>
    public CertificationRequestBuilder()
        : this(KeyFactory.NewKey(SecurityAlgorithms.RsaSha256))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificationRequestBuilder"/> class.
    /// </summary>
    /// <param name="key">The key.</param>
    public CertificationRequestBuilder(IKey key)
    {
        Key = key;
    }

    /// <summary>
    /// Adds the name.
    /// </summary>
    /// <param name="keyOrCommonName">Name of the key or common.</param>
    /// <param name="value">The value.</param>
    /// <exception cref="System.ArgumentOutOfRangeException">
    /// If <paramref name="keyOrCommonName"/> is not a valid X509 name.
    /// </exception>
    public void AddName(string keyOrCommonName, string value)
    {
        if (!_validX509Names.Contains(keyOrCommonName, StringComparer.OrdinalIgnoreCase))
        {
            throw new ArgumentOutOfRangeException(nameof(keyOrCommonName),
                $"The key '{keyOrCommonName}' is not a valid X509 name.");
        }

        _values[keyOrCommonName] = value;
    }

    /// <summary>
    /// Generates the CSR.
    /// </summary>
    /// <returns>
    /// The CSR data.
    /// </returns>
    public byte[] Generate()
    {
        var csr = GeneratePkcs10();
        return csr.CreateSigningRequest(); //.GetDerEncoded();
    }

    private CertificateRequest GeneratePkcs10()
    {
        var x509 = new X500DistinguishedName(string.Join(", ", _values.Select(kv => $"{kv.Key}={kv.Value}")));

        var nameBuilder = new SubjectAlternativeNameBuilder();
        foreach (var altName in SubjectAlternativeNames.Distinct())
        {
            nameBuilder.AddDnsName(altName);
        }
        var altNames = nameBuilder.Build();

        var cr = Key.SecurityKey switch
        {
            RsaSecurityKey rsaKey => new CertificateRequest(x509, rsaKey.Rsa!, Key.HashAlgorithm, RSASignaturePadding.Pss),
            ECDsaSecurityKey ecdsaKey => new CertificateRequest(x509, ecdsaKey.ECDsa!, Key.HashAlgorithm),
            _ => throw new NotSupportedException($"The key algorithm '{Key.Algorithm}' is not supported.")
        };
        cr.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        cr.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment |
            X509KeyUsageFlags.NonRepudiation, true));
        cr.CertificateExtensions.Add(altNames);
        return cr;
    }
}
