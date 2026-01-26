using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;
using OpenCertServer.Ca.Utils.X509.Templates;

namespace OpenCertServer.Ca.Utils;

// ReSharper disable once InconsistentNaming
public class RDNSequenceTemplate : AsnValue
{
    // RDNSequenceTemplate ::= SEQUENCE OF RelativeDistinguishedNameTemplate

    public RDNSequenceTemplate(IEnumerable<RelativeDistinguishedNameTemplate> relativeDistinguishedNames)
    {
        RelativeNames = relativeDistinguishedNames.ToArray();
    }

    public RDNSequenceTemplate(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        List<RelativeDistinguishedNameTemplate> relativeDistinguishedNames = [];
        while (sequenceReader.HasData)
        {
            var relativeName = new RelativeDistinguishedNameTemplate(sequenceReader);
            relativeDistinguishedNames.Add(relativeName);
        }

        RelativeNames = relativeDistinguishedNames.ToArray();
    }

    public RelativeDistinguishedNameTemplate[] RelativeNames { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            foreach (var relativeName in RelativeNames)
            {
                relativeName.Encode(writer);
            }
        }
    }
}
