namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;

/// <summary>
/// Defines the OtherName class.
/// </summary>
/// <code>
/// OtherName ::= SEQUENCE {
///      type-id    OBJECT IDENTIFIER,
///      value      [0] EXPLICIT ANY DEFINED BY type-id }
/// </code>
/// <remarks>
/// Used for SAN entries such as the Microsoft User Principal Name
/// (OID 1.3.6.1.4.1.311.20.2.3), which AD CS and Intune embed in client
/// certificates as a UTF8String wrapped in an otherName.
/// </remarks>
public class OtherName : IAsnValue
{
    private readonly ReadOnlyMemory<byte> _encodedValue;

    /// <summary>
    /// Initializes a new instance of the <see cref="OtherName"/> class.
    /// </summary>
    /// <param name="typeId">The type-id object identifier.</param>
    /// <param name="encodedValue">The DER encoded value (including its own tag).</param>
    public OtherName(string typeId, ReadOnlyMemory<byte> encodedValue)
    {
        TypeId = typeId;
        _encodedValue = encodedValue;
        StringValue = TryReadStringValue(encodedValue);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="OtherName"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
    /// <exception cref="ArgumentException">Thrown if the initial tag is not context specific.</exception>
    public OtherName(AsnReader reader)
    {
        var tag = reader.PeekTag();
        if (tag.TagClass != TagClass.ContextSpecific)
        {
            throw new ArgumentException("Invalid OtherName encoding", nameof(reader));
        }

        var seq = reader.ReadSequence(tag);
        TypeId = seq.ReadObjectIdentifier();
        var valueReader = seq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        _encodedValue = valueReader.ReadEncodedValue();
        StringValue = TryReadStringValue(_encodedValue);
    }

    /// <summary>
    /// Gets the type-id object identifier.
    /// </summary>
    public string TypeId { get; }

    /// <summary>
    /// Gets the decoded character-string value, or <see langword="null"/> when the value is not
    /// a universal character-string type (e.g. UTF8String, IA5String, PrintableString).
    /// </summary>
    public string? StringValue { get; }

    /// <summary>
    /// Gets the raw DER encoded value (including its own tag), as carried in the explicit [0] wrapper.
    /// </summary>
    public ReadOnlyMemory<byte> EncodedValue => _encodedValue;

    private static string? TryReadStringValue(ReadOnlyMemory<byte> encodedValue)
    {
        try
        {
            var reader = new AsnReader(encodedValue, AsnEncodingRules.DER);
            var tag = reader.PeekTag();
            return tag.TagClass == TagClass.Universal
                ? reader.ReadCharacterString((UniversalTagNumber)tag.TagValue)
                : null;
        }
        catch (Exception ex) when (ex is AsnContentException or ArgumentOutOfRangeException)
        {
            // Thrown respectively for malformed encodings and for universal tags that are not
            // one of the recognized character-string types (e.g. INTEGER, BOOLEAN).
            return null;
        }
    }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(TypeId);
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                writer.WriteEncodedValue(_encodedValue.Span);
            }
        }
    }

    /// <inheritdoc/>
    public override string ToString() => StringValue ?? Convert.ToHexString(_encodedValue.Span);
}
