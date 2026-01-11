using System.Formats.Asn1;
using System.Text;

namespace OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the DistributionPointName class.
/// </summary>
/// <code>
/// DistributionPointName ::= CHOICE {
///     fullName                 [0] GeneralNames,
///     nameRelativeToCRLIssuer  [1] RDN
/// }
/// </code>
public class DistributionPointName : AsnValue
{
    public enum DistributionPointNameType
    {
        FullName = 0,
        NameRelativeToCrlIssuer = 1
    }

    private readonly AsnValue _value;

    public DistributionPointName(ReadOnlyMemory<byte> encoded)
        : this(new AsnReader(encoded.ToArray(), AsnEncodingRules.DER))
    {
    }

    public DistributionPointName(AsnReader reader)
    {
        var tag = reader.PeekTag();
        if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            Type = DistributionPointNameType.FullName;
            _value = new GeneralNames(reader);
        }
        else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            Type = DistributionPointNameType.NameRelativeToCrlIssuer;
            _value = new RelativeDistinguishedName(reader);
        }
        else
        {
            throw new ArgumentException("Invalid DistributionPointName encoding", nameof(reader));
        }
    }

    public DistributionPointName(DistributionPointNameType type, AsnValue value)
    {
        Type = type;
        _value = value;
    }

    public DistributionPointNameType Type { get; }

    public GeneralNames? FullName
    {
        get { return Type == DistributionPointNameType.FullName ? (GeneralNames)_value : null; }
    }

    public RelativeDistinguishedName? NameRelativeToCrlIssuer
    {
        get
        {
            return Type == DistributionPointNameType.NameRelativeToCrlIssuer
                ? (RelativeDistinguishedName)_value
                : null;
        }
    }

    public override string ToString()
    {
        var buf = new StringBuilder();
        buf.AppendLine("DistributionPointName: [");
        AppendObject(buf,
            Type == DistributionPointNameType.FullName
                ? "fullName"
                : "nameRelativeToCRLIssuer",
            _value.ToString() ?? "");

        buf.AppendLine("]");
        return buf.ToString();
    }

    public override void Encode(AsnWriter writer, Asn1Tag? tag)
    {
        _value.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, (int)Type));
    }

    private static void AppendObject(StringBuilder buf, string name, string val)
    {
        const string indent = "    ";
        buf.Append(indent);
        buf.Append(name);
        buf.AppendLine(":");
        buf.Append(indent);
        buf.Append(indent);
        buf.Append(val);
        buf.AppendLine();
    }
}
