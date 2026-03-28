namespace OpenCertServer.Ca.Utils.X509.Templates;

using System.Formats.Asn1;
using System.Security.Cryptography;

/// <summary>
/// Represents a template for an X.509 extension, including OID, criticality, and encoded value.
/// </summary>
public class X509ExtensionTemplate : IAsnValue
{
    /// <summary>
    /// Gets the extension object identifier.
    /// </summary>
    public Oid Oid { get; }
    /// <summary>
    /// Gets the extension value payload.
    /// </summary>
    public IAsnValue? Value { get; }
    /// <summary>
    /// Gets a value indicating whether the extension is marked critical.
    /// </summary>
    public bool Critical { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509ExtensionTemplate"/> class.
    /// </summary>
    public X509ExtensionTemplate(Oid oid, IAsnValue? value, bool critical = false)
    {
        Oid = oid;
        Value = value;
        Critical = critical;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509ExtensionTemplate"/> class.
    /// </summary>
    public X509ExtensionTemplate(AsnReader reader)
    {
        var seqReader = reader.ReadSequence();
        Oid = seqReader.ReadObjectIdentifier().InitializeOid();
        if (seqReader.HasData && seqReader.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
        {
            Critical = seqReader.ReadBoolean();
        }

        if (!seqReader.HasData)
        {
            return;
        }

        var octetString = seqReader.ReadOctetString();
        var valueReader = new AsnReader(octetString, AsnEncodingRules.DER);
        Value = new AsnString(Asn1Tag.Null, valueReader.ReadCharacterString(UniversalTagNumber.UTF8String));
    }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence())
        {
            writer.WriteObjectIdentifier(Oid.Value!);
            if (Critical)
            {
                writer.WriteBoolean(true);
            }

            if (Value != null)
            {
                var valueWriter = new AsnWriter(AsnEncodingRules.DER);
                Value.Encode(valueWriter);
                writer.WriteOctetString(valueWriter.Encode());
            }
        }
    }
}
