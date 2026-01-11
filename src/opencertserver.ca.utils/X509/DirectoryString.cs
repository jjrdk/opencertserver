using System.Formats.Asn1;

namespace OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the DirectoryString class.
/// </summary>
/// <code>
/// DirectoryString ::= CHOICE {
///  teletexString           TeletexString (SIZE (1..MAX)),
///  printableString         PrintableString (SIZE (1..MAX)),
///  universalString         UniversalString (SIZE (1..MAX)),
///  utf8String              UTF8String (SIZE (1.. MAX)),
///  bmpString               BMPString (SIZE (1..MAX))
/// }
/// </code>
public class DirectoryString : AsnValue
{
    private readonly string _value;
    private readonly Asn1Tag _type;

    public DirectoryString(string value, UniversalTagNumber type)
    {
        _value = value ?? throw new ArgumentNullException(nameof(value));
        _type = new Asn1Tag(TagClass.ContextSpecific, (int)type);
    }

    public DirectoryString(ReadOnlyMemory<byte> data)
    {
        var reader = new AsnReader(data, AsnEncodingRules.DER);
        _type = reader.PeekTag();
        _value = reader.ReadCharacterString((UniversalTagNumber)_type.TagValue);
    }

    public static implicit operator string(DirectoryString ds) => ds._value;

    public override string ToString()
    {
        return _value;
    }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.WriteCharacterString((UniversalTagNumber)_type.TagValue, _value, tag);
    }
}
