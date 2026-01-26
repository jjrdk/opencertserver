using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils;

public class NameTemplate : AsnValue
{
    /*
    NameTemplate ::= CHOICE {
       -- only one possibility for now --
       rdnSequence RDNSequenceTemplate
    }
     */
    public NameTemplate(RDNSequenceTemplate name)
    {
        Name = name;
    }

    public NameTemplate(AsnReader reader)
    {
        Name = new RDNSequenceTemplate(reader);
    }

    public RDNSequenceTemplate Name { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        Name.Encode(writer);
    }
}
