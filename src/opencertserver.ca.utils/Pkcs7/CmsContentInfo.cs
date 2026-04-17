namespace OpenCertServer.Ca.Utils.Pkcs7;

using System.Formats.Asn1;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the content information for a CMS message, which is a more specific version of the PKCS#7 content information.
/// </summary>
public sealed class CmsContentInfo : IAsnValue
{
    public CmsContentInfo(Oid contentType, IAsnValue encodedContent)
    {
        ContentType = contentType;
        var writer = new AsnWriter(AsnEncodingRules.DER);
        encodedContent.Encode(writer);
        EncodedContent = writer.Encode();
    }

    public CmsContentInfo(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        ContentType = sequenceReader.ReadObjectIdentifier().InitializeOid();
        var contentReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true));
        EncodedContent = contentReader.ReadEncodedValue().ToArray();
    }

    public Oid ContentType { get; }
    public byte[] EncodedContent { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(ContentType.Value!);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, isConstructed: true)))
            {
                writer.WriteEncodedValue(EncodedContent);
            }
        }
    }
}
