namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;

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
public class RelativeDistinguishedName : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RelativeDistinguishedName"/> class.
    /// </summary>
    /// <param name="values">The sequence of values.</param>
    public RelativeDistinguishedName(params Span<AttributeTypeValue> values)
    {
        Values = values.ToArray().AsReadOnly();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RelativeDistinguishedName"/> class.
    /// </summary>
    /// <param name="rawData">The raw DER encoded data.</param>
    public RelativeDistinguishedName(ReadOnlyMemory<byte> rawData)
        : this(new AsnReader(rawData, AsnEncodingRules.DER))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RelativeDistinguishedName"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
    public RelativeDistinguishedName(AsnReader reader)
    {
        List<AttributeTypeValue> values = [];
        // Windows does not enforce the sort order on multi-value RDNs.
        var tag = reader.PeekTag();
        var rdn = reader.ReadSetOf(skipSortOrderValidation: true, expectedTag: tag);
        while (rdn.HasData)
        {
            values.Add(new AttributeTypeValue(rdn));
        }

        Values = values;
    }

    /// <summary>
    /// Gets the collection of attribute type and value pairs.
    /// </summary>
    public IReadOnlyCollection<AttributeTypeValue> Values { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSetOf(tag))
        {
            foreach (var atv in Values)
            {
                atv.Encode(writer);
            }
        }
    }
}
