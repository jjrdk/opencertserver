using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;

namespace OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the AttributeTypeValue class.
/// </summary>
/// <code>
/// AttributeTypeValue ::= SEQUENCE
/// {
///   type               OBJECT IDENTIFIER,
///   value              ANY
/// }
/// </code>
public class AttributeTypeValue : AsnValue
{
    private Asn1Tag _tag;

    /// <summary>
    /// Initializes a new instance of the <see cref="AttributeTypeValue"/> class.
    /// </summary>
    /// <param name="oid">The instance <see cref="Oid"/>.</param>
    /// <param name="tag">The instance <see cref="Asn1Tag"/>.</param>
    /// <param name="value">The instance value as a <see cref="ReadOnlySpan{T}"/>.</param>
    public AttributeTypeValue(Oid oid, Asn1Tag tag, ReadOnlySpan<byte> value)
    {
        _tag = tag;
        Oid = oid;
        Value = Encoding.UTF8.GetString(value);
    }

    public AttributeTypeValue(ReadOnlyMemory<byte> rawData) : this(new AsnReader(rawData, AsnEncodingRules.DER))
    {
    }

    public AttributeTypeValue(AsnReader reader)
    {
        var seq = reader.ReadSequence();
        var oid = seq.ReadObjectIdentifier();
        Oid =oid.InitializeOid();
        _tag = seq.PeekTag();

        if (_tag.TagClass == TagClass.Universal)
        {
            Value = (UniversalTagNumber)_tag.TagValue switch
            {
                UniversalTagNumber.BMPString or UniversalTagNumber.UTF8String or UniversalTagNumber.IA5String
                 or UniversalTagNumber.PrintableString or UniversalTagNumber.NumericString
                 or UniversalTagNumber.T61String => seq.ReadCharacterString((UniversalTagNumber)_tag.TagValue),
                _ => Encoding.UTF8.GetString(seq.ReadOctetString())
            };
        }
        else
        {
            Value = Encoding.UTF8.GetString(seq.ReadOctetString());
        }
    }

    public Oid Oid { get; }
    public string Value { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(Oid.Value!, new Asn1Tag(UniversalTagNumber.ObjectIdentifier));
            writer.WriteCharacterString((UniversalTagNumber)_tag.TagValue, Value);
        }
    }
}
