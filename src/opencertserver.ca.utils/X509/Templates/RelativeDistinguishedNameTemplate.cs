using System.Formats.Asn1;

namespace OpenCertServer.Ca.Utils.X509.Templates;

public class RelativeDistinguishedNameTemplate : AsnValue
{
    public RelativeDistinguishedNameTemplate(IEnumerable<SingleAttributeTemplate> attributes)
    {
        Attributes = attributes.ToList().AsReadOnly();
    }

    public RelativeDistinguishedNameTemplate(AsnReader reader)
    {
        var setReader = reader.ReadSetOf();
        List<SingleAttributeTemplate> attributes = [];
        while (setReader.HasData)
        {
            var template = new SingleAttributeTemplate(setReader);
            attributes.Add(template);
        }
        Attributes = attributes.AsReadOnly();
    }

    public IReadOnlyCollection<SingleAttributeTemplate> Attributes { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSetOf())
        {
            foreach (var attribute in Attributes)
            {
                attribute.Encode(writer);
            }
        }
    }
}
