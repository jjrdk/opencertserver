using System.Formats.Asn1;
using System.Security.Cryptography;

namespace OpenCertServer.Ca.Utils.X509.Templates;

public class SingleAttributeTemplate : AsnValue
{
    public SingleAttributeTemplate(Oid oid, byte[]? rawValue = null)
    {
        Oid = oid;
        RawValue = rawValue;
    }

    public SingleAttributeTemplate(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Oid = sequenceReader.ReadObjectIdentifier().InitializeOid();
        if (reader.HasData)
        {
            RawValue = sequenceReader.ReadOctetString();
        }
    }

    public Oid Oid { get; }

    public byte[]? RawValue { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(Oid.Value!);
            if (RawValue != null)
            {
                writer.WriteOctetString(RawValue);
            }
        }
    }
}
