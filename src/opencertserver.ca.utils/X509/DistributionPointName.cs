namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;
using System.Text;

/// <summary>
/// Defines the DistributionPointName class.
/// </summary>
/// <code>
/// DistributionPointName ::= CHOICE {
///     fullName                 [0] GeneralNames,
///     nameRelativeToCRLIssuer  [1] RDN
/// }
/// </code>
public class DistributionPointName : IAsnValue
{
    /// <summary>
    /// Defines the types of DistributionPointName.
    /// </summary>
    public enum DistributionPointNameType
    {
        FullName = 0,
        NameRelativeToCrlIssuer = 1
    }

    private readonly IAsnValue _value;

    /// <summary>
    /// Initializes a new instance of the <see cref="DistributionPointName"/> class.
    /// </summary>
    /// <param name="encoded">The raw DER encoded data.</param>
    public DistributionPointName(ReadOnlyMemory<byte> encoded)
        : this(new AsnReader(encoded.ToArray(), AsnEncodingRules.DER))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DistributionPointName"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
    /// <exception cref="ArgumentException">Thrown if the initial tag does not match the defined choices.</exception>
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

    /// <summary>
    /// Initializes a new instance of the <see cref="DistributionPointName"/> class.
    /// </summary>
    /// <param name="type">The name type.</param>
    /// <param name="value">The name value.</param>
    public DistributionPointName(DistributionPointNameType type, IAsnValue value)
    {
        Type = type;
        _value = value;
    }

    /// <summary>
    /// Gets the distribution point name type.
    /// </summary>
    public DistributionPointNameType Type { get; }

    /// <summary>
    /// Gets the optional full name.
    /// </summary>
    public GeneralNames? FullName
    {
        get { return Type == DistributionPointNameType.FullName ? (GeneralNames)_value : null; }
    }

    /// <summary>
    /// Gets the optional name relative to CRL issuer.
    /// </summary>
    public RelativeDistinguishedName? NameRelativeToCrlIssuer
    {
        get
        {
            return Type == DistributionPointNameType.NameRelativeToCrlIssuer
                ? (RelativeDistinguishedName)_value
                : null;
        }
    }

    /// <inheritdoc/>
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

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag)
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
