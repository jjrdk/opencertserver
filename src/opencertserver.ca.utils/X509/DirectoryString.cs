namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;

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
public class DirectoryString : IAsnValue
{
    private readonly string _value;
    private readonly Asn1Tag _type;

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryString"/> class.
    /// </summary>
    /// <param name="value">The string value.</param>
    /// <param name="type">The type of string.</param>
    /// <exception cref="ArgumentNullException"></exception>
    public DirectoryString(string value, UniversalTagNumber type)
    {
        _value = value ?? throw new ArgumentNullException(nameof(value));
        _type = new Asn1Tag(TagClass.ContextSpecific, (int)type);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DirectoryString"/> class.
    /// </summary>
    /// <param name="data">The raw DER formatted data.</param>
    public DirectoryString(ReadOnlyMemory<byte> data)
    {
        var reader = new AsnReader(data, AsnEncodingRules.DER);
        _type = reader.PeekTag();
        _value = reader.ReadCharacterString((UniversalTagNumber)_type.TagValue);
    }

    /// <summary>
    /// Converts a DirectoryString to a string.
    /// </summary>
    /// <param name="ds">The directory string to convert.</param>
    /// <returns>A <see cref="string"/> instance.</returns>
    public static implicit operator string(DirectoryString ds) => ds._value;

    /// <inheritdoc/>
    public override string ToString()
    {
        return _value;
    }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.WriteCharacterString((UniversalTagNumber)_type.TagValue, _value, tag);
    }
}
