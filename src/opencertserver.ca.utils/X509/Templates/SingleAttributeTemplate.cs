using System.Formats.Asn1;

namespace OpenCertServer.Ca.Utils.X509.Templates;

public class SingleAttributeTemplate : AsnValue
{
    public SingleAttributeTemplate(string oid, byte[]? rawValue = null)
    {
        Oid = oid;
        RawValue = rawValue;
    }

    public SingleAttributeTemplate(AsnReader reader)
    {
        Oid = reader.ReadObjectIdentifier();
        if (reader.HasData)
        {
            RawValue = reader.ReadOctetString();
        }
    }

    public string Oid { get; }

    public byte[]? RawValue { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(Oid);
            if (RawValue != null)
            {
                writer.WriteOctetString(RawValue);
            }
        }
    }
}
