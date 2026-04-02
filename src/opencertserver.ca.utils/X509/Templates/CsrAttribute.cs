namespace OpenCertServer.Ca.Utils.X509.Templates;

using System.Formats.Asn1;
using System.Security.Cryptography;

/// <summary>
/// Represents a legacy RFC 7030 CSR attribute.
/// </summary>
public sealed class CsrAttribute : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CsrAttribute"/> class.
    /// </summary>
    public CsrAttribute(Oid oid, IEnumerable<IAsnValue>? values = null)
    {
        Oid = oid;
        Values = (values ?? []).Select(value => value.GetBytes()).ToArray();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CsrAttribute"/> class.
    /// </summary>
    public CsrAttribute(Oid oid, IEnumerable<byte[]> values)
    {
        Oid = oid;
        Values = values.ToArray();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CsrAttribute"/> class.
    /// </summary>
    public CsrAttribute(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Oid = sequenceReader.ReadObjectIdentifier().InitializeOid();

        List<byte[]> values = [];
        if (sequenceReader.HasData)
        {
            var valuesReader = sequenceReader.ReadSetOf();
            while (valuesReader.HasData)
            {
                values.Add(valuesReader.ReadEncodedValue().ToArray());
            }
        }

        Values = values.AsReadOnly();
    }

    /// <summary>
    /// Gets the attribute type OID.
    /// </summary>
    public Oid Oid { get; }

    /// <summary>
    /// Gets the encoded attribute values.
    /// </summary>
    public IReadOnlyList<byte[]> Values { get; }

    /// <inheritdoc />
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(Oid.Value!);
            using (writer.PushSetOf())
            {
                foreach (var value in Values)
                {
                    writer.WriteEncodedValue(value);
                }
            }
        }
    }
}

