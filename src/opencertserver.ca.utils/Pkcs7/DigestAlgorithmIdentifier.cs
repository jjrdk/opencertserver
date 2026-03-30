namespace OpenCertServer.Ca.Utils.Pkcs7;

using System.Formats.Asn1;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the digest algorithm identifier for PKCS#7 content.
/// </summary>
public class DigestAlgorithmIdentifier : AlgorithmIdentifier
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DigestAlgorithmIdentifier"/> class from an ASN.1 reader.
    /// </summary>
    /// <param name="reader">The ASN.1 reader to read the digest algorithm identifier from.</param>
    public DigestAlgorithmIdentifier(AsnReader reader) : base(reader)
    {
        AlgorithmIdentifier = new Oid(reader.ReadObjectIdentifier());
        Parameters = reader.ReadEncodedValue().ToArray();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DigestAlgorithmIdentifier"/> class with the specified algorithm identifier and parameters.
    /// </summary>
    /// <param name="algorithmIdentifier">The algorithm identifier for the digest algorithm.</param>
    /// <param name="parameters">The parameters for the digest algorithm.</param>
    public DigestAlgorithmIdentifier(Oid algorithmIdentifier, byte[] parameters) : base(algorithmIdentifier)
    {
        AlgorithmIdentifier = algorithmIdentifier;
        Parameters = parameters;
    }

    /// <summary>
    /// Gets the algorithm identifier for the digest algorithm.
    /// </summary>
    public Oid AlgorithmIdentifier { get; }

    /// <summary>
    /// Gets the parameters for the digest algorithm.
    /// </summary>
    public byte[] Parameters { get; }
}
