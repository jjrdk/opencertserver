namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;

/// <summary>
/// Defines a simple ASN.1 string value with a specified tag.
/// </summary>
public class AsnString : IAsnValue
{
    private readonly Asn1Tag _tag;

    /// <summary>
    /// Initializes a new instance of the <see cref="AsnString"/> class.
    /// </summary>
    /// <param name="tag">The <see cref="Asn1Tag"/> for the string value.</param>
    /// <param name="value">The string value.</param>
    public AsnString(Asn1Tag tag, string value)
    {
        _tag = tag;
        Value = value;
    }

    /// <summary>
    /// Gets the string value.
    /// </summary>
    public string Value { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.WriteCharacterString((UniversalTagNumber)_tag.TagValue, Value, tag);
    }

    /// <summary>
    /// Defines an implicit conversion from <see cref="AsnString"/> to <see cref="string"/>.
    /// </summary>
    /// <param name="asnString">The <see cref="AsnString"/> to convert.</param>
    /// <returns></returns>
    public static implicit operator string(AsnString asnString) => asnString.Value;

    /// <inheritdoc/>
    public override string ToString() => Value;
}
