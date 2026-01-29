namespace OpenCertServer.Ca.Utils;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;
using OpenCertServer.Ca.Utils.X509.Templates;

/// <summary>
/// Defines a template for a sequence of relative distinguished names.
/// </summary>
/// <code>
/// RDNSequenceTemplate ::= SEQUENCE OF RelativeDistinguishedNameTemplate
/// </code>
// ReSharper disable once InconsistentNaming
public class RDNSequenceTemplate : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RDNSequenceTemplate"/> class.
    /// </summary>
    /// <param name="relativeDistinguishedNames">The sequence of <see cref="RelativeDistinguishedNameTemplate"/>.</param>
    public RDNSequenceTemplate(IEnumerable<RelativeDistinguishedNameTemplate> relativeDistinguishedNames)
    {
        RelativeNames = relativeDistinguishedNames.ToArray();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RDNSequenceTemplate"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read the content from.</param>
    public RDNSequenceTemplate(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        List<RelativeDistinguishedNameTemplate> relativeDistinguishedNames = [];
        while (sequenceReader.HasData)
        {
            var relativeName = new RelativeDistinguishedNameTemplate(sequenceReader);
            relativeDistinguishedNames.Add(relativeName);
        }

        RelativeNames = relativeDistinguishedNames.ToArray();
    }

    /// <summary>
    /// Gets the relative distinguished names in the sequence.
    /// </summary>
    public RelativeDistinguishedNameTemplate[] RelativeNames { get; }

    /// <inheritdoc />
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            foreach (var relativeName in RelativeNames)
            {
                relativeName.Encode(writer);
            }
        }
    }
}
