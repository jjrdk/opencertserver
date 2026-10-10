using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Pkcs7;

/// <summary>
/// RFC 5652 UnprotectedAttributes.
/// </summary>
/// <code>
/// UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute
/// </code>
public sealed class UnprotectedAttributes : IAsnValue
{
    public UnprotectedAttributes(IEnumerable<byte[]> attributes)
    {
        Attributes = attributes.Select(v => v.ToArray()).ToArray();
    }

    public UnprotectedAttributes(AsnReader reader)
    {
        // Decode as [1] IMPLICIT SET, symmetric with Encode(writer, [1]).
        var setReader = reader.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 1));
        List<byte[]> attributes = [];
        while (setReader.HasData)
        {
            attributes.Add(setReader.ReadEncodedValue().ToArray());
        }

        Attributes = attributes;
    }

    public IReadOnlyList<byte[]> Attributes { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSetOf(tag))
        {
            foreach (var attribute in Attributes)
            {
                writer.WriteEncodedValue(attribute);
            }
        }
    }
}