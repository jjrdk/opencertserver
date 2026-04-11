namespace OpenCertServer.Ca.Utils.X509.Templates;

using System.Formats.Asn1;
using System.Security.Cryptography;

/// <summary>
/// Represents a CSR attributes response containing legacy RFC 7030 elements and/or RFC 9908 templates.
/// </summary>
public sealed class CsrAttributes : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CsrAttributes"/> class.
    /// </summary>
    public CsrAttributes(
        IEnumerable<Oid>? objectIdentifiers = null,
        IEnumerable<CsrAttribute>? attributes = null,
        IEnumerable<CertificateSigningRequestTemplate>? templates = null)
    {
        ObjectIdentifiers = (objectIdentifiers ?? []).ToArray();
        Attributes = (attributes ?? []).ToArray();
        Templates = (templates ?? []).ToArray();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CsrAttributes"/> class.
    /// </summary>
    public CsrAttributes(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        List<Oid> objectIdentifiers = [];
        List<CsrAttribute> attributes = [];
        List<CertificateSigningRequestTemplate> templates = [];

        while (sequenceReader.HasData)
        {
            var tag = sequenceReader.PeekTag();
            if (tag.HasSameClassAndValue(Asn1Tag.ObjectIdentifier))
            {
                objectIdentifiers.Add(sequenceReader.ReadObjectIdentifier().InitializeOid());
                continue;
            }

            if (tag.HasSameClassAndValue(Asn1Tag.Sequence))
            {
                var encodedValue = sequenceReader.ReadEncodedValue().ToArray();
                var elementReader = new AsnReader(encodedValue, AsnEncodingRules.DER,
                    new AsnReaderOptions { SkipSetSortOrderVerification = true });
                var sequenceValueReader = elementReader.ReadSequence();
                var firstTag = sequenceValueReader.PeekTag();

                if (firstTag.HasSameClassAndValue(Asn1Tag.Integer))
                {
                    templates.Add(new CertificateSigningRequestTemplate(
                        new AsnReader(encodedValue, AsnEncodingRules.DER,
                            new AsnReaderOptions { SkipSetSortOrderVerification = true })));
                    continue;
                }

                if (firstTag.HasSameClassAndValue(Asn1Tag.ObjectIdentifier))
                {
                    attributes.Add(new CsrAttribute(
                        new AsnReader(encodedValue, AsnEncodingRules.DER,
                            new AsnReaderOptions { SkipSetSortOrderVerification = true })));
                }
            }
        }

        ObjectIdentifiers = objectIdentifiers.AsReadOnly();
        Attributes = attributes.AsReadOnly();
        Templates = templates.AsReadOnly();
    }

    /// <summary>
    /// Gets the bare OID requirements from the response.
    /// </summary>
    public IReadOnlyList<Oid> ObjectIdentifiers { get; }

    /// <summary>
    /// Gets the legacy attribute requirements from the response.
    /// </summary>
    public IReadOnlyList<CsrAttribute> Attributes { get; }

    /// <summary>
    /// Gets the RFC 9908 template requirements from the response.
    /// </summary>
    public IReadOnlyList<CertificateSigningRequestTemplate> Templates { get; }

    /// <summary>
    /// Gets a value indicating whether any CSR attribute elements are present.
    /// </summary>
    public bool HasValues
    {
        get { return ObjectIdentifiers.Count > 0 || Attributes.Count > 0 || Templates.Count > 0; }
    }

    /// <summary>
    /// Returns the first template, if any.
    /// </summary>
    public CertificateSigningRequestTemplate? GetPreferredTemplate()
    {
        return Templates.FirstOrDefault();
    }

    /// <summary>
    /// Finds a legacy CSR attribute by OID.
    /// </summary>
    public CsrAttribute? FindAttribute(string oid)
    {
        return Attributes.FirstOrDefault(attribute => attribute.Oid.Value == oid);
    }

    /// <inheritdoc />
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            foreach (var objectIdentifier in ObjectIdentifiers)
            {
                writer.WriteObjectIdentifier(objectIdentifier.Value!);
            }

            foreach (var attribute in Attributes)
            {
                attribute.Encode(writer);
            }

            foreach (var template in Templates)
            {
                template.Encode(writer);
            }
        }
    }
}

