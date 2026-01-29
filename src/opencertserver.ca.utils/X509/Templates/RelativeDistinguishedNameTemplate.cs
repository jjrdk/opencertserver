namespace OpenCertServer.Ca.Utils.X509.Templates;

using System.Formats.Asn1;

/// <summary>
/// Defines a template for a Relative Distinguished Name (RDN) in X.509 certificates.
/// </summary>
/// <code>
///  RelativeDistinguishedNameTemplate ::= SET SIZE (1 .. MAX)
///    OF SingleAttributeTemplate { {SupportedAttributes} }
/// </code>
public class RelativeDistinguishedNameTemplate : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RelativeDistinguishedNameTemplate"/> class.
    /// </summary>
    /// <param name="attributes">A sequence of <see cref="SingleAttributeTemplate"/> values.</param>
    public RelativeDistinguishedNameTemplate(IEnumerable<SingleAttributeTemplate> attributes)
    {
        Attributes = attributes.ToList().AsReadOnly();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RelativeDistinguishedNameTemplate"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
    public RelativeDistinguishedNameTemplate(AsnReader reader)
    {
        var setReader = reader.ReadSetOf();
        List<SingleAttributeTemplate> attributes = [];
        while (setReader.HasData)
        {
            var template = new SingleAttributeTemplate(setReader);
            attributes.Add(template);
        }
        Attributes = attributes.AsReadOnly();
    }

    /// <summary>
    /// Gets the collection of <see cref="SingleAttributeTemplate"/> values.
    /// </summary>
    public IReadOnlyCollection<SingleAttributeTemplate> Attributes { get; }

    /// <inheritdoc />
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSetOf())
        {
            foreach (var attribute in Attributes)
            {
                attribute.Encode(writer);
            }
        }
    }
}
