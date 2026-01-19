using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.X509Extensions.Templates;

public class SingleAttributeTemplate : AsnValue
{
    public SingleAttributeTemplate(string oid, byte[]? rawValue)
    {
        Oid = oid;
        RawValue = rawValue;
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
