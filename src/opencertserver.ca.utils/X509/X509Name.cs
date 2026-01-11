using System.Formats.Asn1;

namespace OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the X509Name class.
/// </summary>
/// <code>
/// Name ::= SEQUENCE OF RelativeDistinguishedName
/// </code>
public class X509Name : AsnValue
{
    public IReadOnlyCollection<RelativeDistinguishedName> RelativeDistinguishedNames { get; }

    public X509Name(ReadOnlyMemory<byte> rawData) : this(new AsnReader(rawData, AsnEncodingRules.DER))
    {
    }

    public X509Name(AsnReader outer)
    {
        var values = new List<RelativeDistinguishedName>();
        while (outer.HasData)
        {
            values.Add(new RelativeDistinguishedName(outer.ReadSequence()));
        }

        RelativeDistinguishedNames = values.AsReadOnly();
    }

    public X509Name(params IEnumerable<RelativeDistinguishedName> relativeDistinguishedNames)
    {
        RelativeDistinguishedNames = relativeDistinguishedNames.ToList().AsReadOnly();
    }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            foreach (var rdn in RelativeDistinguishedNames)
            {
                rdn.Encode(writer);
            }
        }
    }
}
