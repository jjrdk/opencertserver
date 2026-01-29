namespace OpenCertServer.Ca.Utils;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the NameTemplate structure.
/// </summary>
/// <code>
/// NameTemplate ::= CHOICE {
/// -- only one possibility for now --
/// rdnSequence RDNSequenceTemplate
/// }
/// </code>
public class NameTemplate : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="NameTemplate"/> class.
    /// </summary>
    /// <param name="name">The template.</param>
    public NameTemplate(RDNSequenceTemplate name)
    {
        Name = name;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="NameTemplate"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read the content from.</param>
    public NameTemplate(AsnReader reader)
    {
        Name = new RDNSequenceTemplate(reader);
    }

    /// <summary>
    /// Gets the name template.
    /// </summary>
    public RDNSequenceTemplate Name { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        Name.Encode(writer);
    }
}
