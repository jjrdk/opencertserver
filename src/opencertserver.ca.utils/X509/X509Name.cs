namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;

/// <summary>
/// Defines the X509Name class.
/// </summary>
/// <code>
/// Name ::= SEQUENCE OF RelativeDistinguishedName
/// </code>
public class X509Name : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="X509Name"/> class.
    /// </summary>
    /// <param name="rawData">The raw DER encoded data.</param>
    public X509Name(ReadOnlyMemory<byte> rawData) : this(new AsnReader(rawData, AsnEncodingRules.DER))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509Name"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
    public X509Name(AsnReader reader)
    {
        var values = new List<RelativeDistinguishedName>();
        while (reader.HasData)
        {
            values.Add(new RelativeDistinguishedName(reader.ReadSequence()));
        }

        RelativeDistinguishedNames = values.AsReadOnly();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509Name"/> class.
    /// </summary>
    /// <param name="relativeDistinguishedNames">The sequence of relative distinguished names.</param>
    public X509Name(params Span<RelativeDistinguishedName> relativeDistinguishedNames)
    {
        RelativeDistinguishedNames = relativeDistinguishedNames.ToArray().AsReadOnly();
    }

    /// <summary>
    /// Gets the collection of relative distinguished names.
    /// </summary>
    public IReadOnlyCollection<RelativeDistinguishedName> RelativeDistinguishedNames { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            foreach (var rdn in RelativeDistinguishedNames)
            {
                rdn.Encode(writer);
            }
        }
    }
}
