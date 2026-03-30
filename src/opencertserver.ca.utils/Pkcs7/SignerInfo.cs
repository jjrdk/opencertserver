namespace OpenCertServer.Ca.Utils.Pkcs7;

using System.Formats.Asn1;
using System.Numerics;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the SignerInfo structure as per PKCS#7 standard.
/// </summary>
/// <code>
/// SignerInfo ::= SEQUENCE {
///     version                     Version,
///     issuerAndSerialNumber       IssuerAndSerialNumber,
///     digestAlgorithm             DigestAlgorithmIdentifier,
///     authenticatedAttributes     [0] IMPLICIT Attributes OPTIONAL,
///     digestEncryptionAlgorithm   DigestEncryptionAlgorithmIdentifier,
///     encryptedDigest             EncryptedDigest,
///     unauthenticatedAttributes   [1] IMPLICIT Attributes OPTIONAL
/// }
///
/// EncryptedDigest ::= OCTET STRING DigestAlgorithmIdentifier ::= AlgorithmIdentifier
/// DigestEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier
/// </code>
public class SignerInfo : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SignerInfo"/> class.
    /// </summary>
    /// <param name="reader">The ASN.1 reader containing the SignerInfo data.</param>
    public SignerInfo(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Version = sequenceReader.ReadInteger();
        IssuerAndSerialNumber = new IssuerAndSerialNumber(sequenceReader);
        DigestAlgorithm = new DigestAlgorithmIdentifier(sequenceReader);
        var tag = sequenceReader.PeekTag();
        if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            var authenticatedAttributesReader =
                sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: false));
            AuthenticatedAttributes = authenticatedAttributesReader.ReadEncodedValue().ToArray();
        }

        DigestEncryptionAlgorithm = new DigestAlgorithmIdentifier(sequenceReader);
        EncryptedDigest = sequenceReader.ReadOctetString();
        tag = sequenceReader.PeekTag();
        if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            var unauthenticatedAttributesReader =
                sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: false));
            UnauthenticatedAttributes = unauthenticatedAttributesReader.ReadEncodedValue().ToArray();
        }
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SignerInfo"/> class.
    /// </summary>
    /// <param name="version">The version of the SignerInfo.</param>
    /// <param name="issuerAndSerialNumber">The issuer and serial number of the signer.</param>
    /// <param name="digestAlgorithm">The digest algorithm used for signing.</param>
    /// <param name="authenticatedAttributes">The authenticated attributes associated with the signer.</param>
    /// <param name="digestEncryptionAlgorithm">The digest encryption algorithm used for encryption.</param>
    /// <param name="encryptedDigest">The encrypted digest of the signed data.</param>
    /// <param name="unauthenticatedAttributes">The unauthenticated attributes associated with the signer.</param>
    public SignerInfo(
        BigInteger version,
        IssuerAndSerialNumber issuerAndSerialNumber,
        DigestAlgorithmIdentifier digestAlgorithm,
        byte[]? authenticatedAttributes,
        DigestAlgorithmIdentifier digestEncryptionAlgorithm,
        byte[] encryptedDigest,
        byte[]? unauthenticatedAttributes)
    {
        Version = version;
        IssuerAndSerialNumber = issuerAndSerialNumber;
        DigestAlgorithm = digestAlgorithm;
        AuthenticatedAttributes = authenticatedAttributes;
        DigestEncryptionAlgorithm = digestEncryptionAlgorithm;
        EncryptedDigest = encryptedDigest;
        UnauthenticatedAttributes = unauthenticatedAttributes;
    }

    /// <summary>
    /// Gets the version of the SignerInfo.
    /// </summary>
    public BigInteger Version { get; }

    /// <summary>
    /// Gets the issuer and serial number of the signer.
    /// </summary>
    public IssuerAndSerialNumber IssuerAndSerialNumber { get; }

    /// <summary>
    /// Gets the digest algorithm used for signing.
    /// </summary>
    public DigestAlgorithmIdentifier DigestAlgorithm { get; }

    /// <summary>
    /// Gets the authenticated attributes associated with the signer.
    /// </summary>
    public byte[]? AuthenticatedAttributes { get; }

    /// <summary>
    /// Gets the digest encryption algorithm used for encryption.
    /// </summary>
    public DigestAlgorithmIdentifier DigestEncryptionAlgorithm { get; }

    /// <summary>
    /// Gets the encrypted digest of the signed data.
    /// </summary>
    public byte[] EncryptedDigest { get; }

    /// <summary>
    /// Gets the unauthenticated attributes associated with the signer.
    /// </summary>
    public byte[]? UnauthenticatedAttributes { get; }

    /// <inheritdoc />
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteInteger(Version);
            IssuerAndSerialNumber.Encode(writer);
            DigestAlgorithm.Encode(writer);
            if (AuthenticatedAttributes != null)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: false)))
                {
                    writer.WriteEncodedValue(AuthenticatedAttributes);
                }
            }

            DigestEncryptionAlgorithm.Encode(writer);
            writer.WriteOctetString(EncryptedDigest);
            if (UnauthenticatedAttributes != null)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, isConstructed: false)))
                {
                    writer.WriteEncodedValue(UnauthenticatedAttributes);
                }
            }
        }
    }
}
