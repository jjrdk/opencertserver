namespace OpenCertServer.Ca.Utils.X509.Templates;

using System.Formats.Asn1;
using System.Security.Cryptography;

/// <summary>
/// Defines the SingleAttributeTemplate ASN.1 structure.
/// </summary>
/// <code>
/// SingleAttributeTemplate{ATTRIBUTE:AttrSet} ::= SEQUENCE {
///    type ATTRIBUTE.&id({AttrSet}),
///    value ATTRIBUTE.&Type({AttrSet}{@type}) OPTIONAL
/// }
/// </code>
public class SingleAttributeTemplate : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SingleAttributeTemplate"/> class.
    /// </summary>
    /// <param name="oid">The <see cref="Oid"/> value.</param>
    /// <param name="rawValue">The optional <see cref="byte"/> array value.</param>
    public SingleAttributeTemplate(Oid oid, byte[]? rawValue = null)
    {
        Oid = oid;
        RawValue = rawValue;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SingleAttributeTemplate"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read the attribute.</param>
    public SingleAttributeTemplate(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Oid = sequenceReader.ReadObjectIdentifier().InitializeOid();
        if (reader.HasData)
        {
            RawValue = sequenceReader.ReadOctetString();
        }
    }

    /// <summary>
    /// Gets the OID of the attribute.
    /// </summary>
    public Oid Oid { get; }

    /// <summary>
    /// Gets the raw value of the attribute, if present.
    /// </summary>
    public byte[]? RawValue { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(Oid.Value!);
            if (RawValue != null)
            {
                writer.WriteOctetString(RawValue);
            }
        }
    }
}
