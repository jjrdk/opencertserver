using System.Formats.Asn1;

namespace OpenCertServer.Ca.Utils.X509;

public abstract class AsnValue
{
    public abstract void Encode(AsnWriter writer, Asn1Tag? tag = null);
}

public class AsnString : AsnValue
{
    public AsnString(Asn1Tag tag, string value)
    {
        _tag = tag;
        Value = value;
    }

    private Asn1Tag _tag;

    public string Value { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.WriteCharacterString((UniversalTagNumber)_tag.TagValue, Value, tag);
    }

    public static implicit operator string(AsnString asnString) => asnString.Value;

    public override string ToString() => Value;
}
