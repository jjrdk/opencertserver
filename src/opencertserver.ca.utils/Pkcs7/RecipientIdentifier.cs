using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Pkcs7;

/// <summary>
/// RFC 5652 RecipientIdentifier.
/// </summary>
/// <code>
/// RecipientIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier
/// }
/// </code>
public sealed class RecipientIdentifier : IAsnValue
{
    public RecipientIdentifier(IssuerAndSerialNumber issuerAndSerialNumber)
    {
        IssuerAndSerialNumber = issuerAndSerialNumber;
    }

    public RecipientIdentifier(byte[] subjectKeyIdentifier)
    {
        SubjectKeyIdentifier = subjectKeyIdentifier.ToArray();
    }

    public RecipientIdentifier(AsnReader reader)
    {
        var tag = reader.PeekTag();
        if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            SubjectKeyIdentifier = reader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 0));
            return;
        }

        IssuerAndSerialNumber = new IssuerAndSerialNumber(reader);
    }

    public IssuerAndSerialNumber? IssuerAndSerialNumber { get; }

    public byte[]? SubjectKeyIdentifier { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        if (SubjectKeyIdentifier != null)
        {
            writer.WriteOctetString(SubjectKeyIdentifier, new Asn1Tag(TagClass.ContextSpecific, 0));
            return;
        }

        IssuerAndSerialNumber?.Encode(writer, tag);
    }
}