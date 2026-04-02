namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;

/// <summary>
/// Defines a simple ASN.1 octet-string value with a specified tag.
/// </summary>
public class AsnOctetString : IAsnValue
{
    private readonly Asn1Tag _tag;

    /// <summary>
    /// Initializes a new instance of the <see cref="AsnOctetString"/> class.
    /// </summary>
    /// <param name="tag">The <see cref="Asn1Tag"/> for the octet-string value.</param>
    /// <param name="value">The octet-string value.</param>
    public AsnOctetString(Asn1Tag tag, byte[] value)
    {
        _tag = tag;
        Value = value;
    }

    /// <summary>
    /// Gets the octet-string value.
    /// </summary>
    public byte[] Value { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.WriteOctetString(Value, tag ?? _tag);
    }

    /// <inheritdoc/>
    public override string ToString() => Convert.ToHexString(Value);
}
