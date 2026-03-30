using System.Formats.Asn1;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Pkcs7;

/// <summary>
/// Defines the content information for a PKCS#7 message.
/// </summary>
/// <code>
/// ContentInfo ::= SEQUENCE {
///     contentType ContentType,
///     content     [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
/// }
/// </code>
public class ContentInfo : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ContentInfo"/> class.
    /// </summary>
    /// <param name="contentType">The content type of the message.</param>
    /// <param name="content">The content of the message.</param>
    public ContentInfo(Oid contentType, byte[] content)
    {
        ContentType = contentType;
        Content = content;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ContentInfo"/> class from an ASN.1 reader.
    /// </summary>
    /// <param name="reader">The ASN.1 reader to read the content information from.</param>
    public ContentInfo(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        ContentType = new Oid(sequenceReader.ReadObjectIdentifier());
        if (sequenceReader.HasData)
        {
            var contentReader =
                sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
            Content = contentReader.ReadOctetString();
        }
        else
        {
            Content = [];
        }
    }

    /// <summary>
    /// Gets the object identifier of the content type.
    /// </summary>
    public Oid ContentType { get; }

    /// <summary>
    /// Gets the content of the message.
    /// </summary>
    public byte[] Content { get; }

    /// <inheritdoc />
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(ContentType.Value!);
            if (Content.Length > 0)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
                {
                    writer.WriteOctetString(Content);
                }
            }
        }
    }
}
