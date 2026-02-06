namespace OpenCertServer.Ca.Utils.X509.Templates;

using System.Formats.Asn1;

/// <summary>
/// Defines the SubjectPublicKeyInfoTemplate ASN.1 structure.
/// </summary>
/// <code>
/// SubjectPublicKeyInfoTemplate{PUBLIC-KEY:IOSet} ::= SEQUENCE {
///    algorithm AlgorithmIdentifier{PUBLIC-KEY, {IOSet}},
///    subjectPublicKey BIT STRING OPTIONAL
/// }
/// </code>
public class SubjectPublicKeyInfoTemplate : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SubjectPublicKeyInfoTemplate"/> class.
    /// </summary>
    /// <param name="algorithmIdentifier">The algorithm <see cref="AlgorithmIdentifier"/>.</param>
    /// <param name="publicKey">The subject public key.</param>
    public SubjectPublicKeyInfoTemplate(AlgorithmIdentifier algorithmIdentifier, byte[]? publicKey = null)
    {
        AlgorithmIdentifier = algorithmIdentifier;
        PublicKey = publicKey;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SubjectPublicKeyInfoTemplate"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
    /// <param name="expectedTag">The expected <see cref="Asn1Tag"/> for the content.</param>
    public SubjectPublicKeyInfoTemplate(AsnReader reader, Asn1Tag? expectedTag = null)
    {
        var sequenceReader = reader.ReadSequence(expectedTag);
        AlgorithmIdentifier = new AlgorithmIdentifier(sequenceReader);
        if (sequenceReader.HasData)
        {
            PublicKey = sequenceReader.ReadBitString(out _);
        }
    }

    /// <summary>
    /// Gets the algorithm <see cref="AlgorithmIdentifier"/>.
    /// </summary>
    public AlgorithmIdentifier AlgorithmIdentifier { get; }

    /// <summary>
    /// Gets the subject public key.
    /// </summary>
    public byte[]? PublicKey { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            AlgorithmIdentifier.Encode(writer);

            if (PublicKey != null)
            {
                writer.WriteBitString(PublicKey.AsSpan());
            }
        }
    }
}
