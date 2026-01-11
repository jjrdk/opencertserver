using System.Formats.Asn1;

namespace OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the RelativeDistinguishedName class.
/// </summary>
/// <code>
/// Name ::= SEQUENCE OF RelativeDistinguishedName
///
/// RelativeDistinguishedName ::= SET OF AttributeTypeValue
///
/// AttributeTypeValue ::= SEQUENCE
/// {
///   type               OBJECT IDENTIFIER,
///   value              ANY
/// }
/// </code>
public class RelativeDistinguishedName : AsnValue
{
    public RelativeDistinguishedName(params AttributeTypeValue[] values)
    {
        Values = values.AsReadOnly();
    }

    public RelativeDistinguishedName(ReadOnlyMemory<byte> rawData)
        : this(new AsnReader(rawData, AsnEncodingRules.DER))
    {
    }

    public RelativeDistinguishedName(AsnReader outer)
    {
        List<AttributeTypeValue> values = [];
        // Windows does not enforce the sort order on multi-value RDNs.
        var tag = outer.PeekTag();
        var rdn = outer.ReadSetOf(skipSortOrderValidation: true, expectedTag: tag);
        while (rdn.HasData)
        {
            values.Add(new AttributeTypeValue(rdn));
        }

        Values = values;
    }

    public IReadOnlyCollection<AttributeTypeValue> Values { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSetOf(tag))
        {
            foreach (var atv in Values)
            {
                atv.Encode(writer, null);
            }
        }
    }
}
