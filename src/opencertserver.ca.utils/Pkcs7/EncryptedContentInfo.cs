using System.Formats.Asn1;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Pkcs7;

/// <summary>
/// RFC 5652 EncryptedContentInfo.
/// </summary>
/// <code>
/// EncryptedContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
///   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL
/// }
///
/// EncryptedContent ::= OCTET STRING
/// </code>
public sealed class EncryptedContentInfo : IAsnValue
{
    public EncryptedContentInfo(
        Oid contentType,
        CmsAlgorithmIdentifier contentEncryptionAlgorithm,
        byte[]? encryptedContent)
    {
        ContentType = contentType;
        ContentEncryptionAlgorithm = contentEncryptionAlgorithm;
        EncryptedContent = encryptedContent?.ToArray();
    }

    public EncryptedContentInfo(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        ContentType = sequenceReader.ReadObjectIdentifier().InitializeOid();
        ContentEncryptionAlgorithm = new CmsAlgorithmIdentifier(sequenceReader);
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            EncryptedContent = sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
        }

        sequenceReader.ThrowIfNotEmpty();
    }

    public Oid ContentType { get; }

    public CmsAlgorithmIdentifier ContentEncryptionAlgorithm { get; }

    public byte[]? EncryptedContent { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(ContentType.Value!);
            ContentEncryptionAlgorithm.Encode(writer);
            if (EncryptedContent != null)
            {
                writer.WriteOctetString(EncryptedContent, new Asn1Tag(TagClass.ContextSpecific, 0));
            }
        }
    }
}