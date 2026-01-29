namespace OpenCertServer.Ca.Utils.X509.Templates;

using System.Formats.Asn1;
using System.Security.Cryptography;

public class X509ExtensionTemplate : IAsnValue
{
    public Oid Oid { get; }
    public IAsnValue? Value { get; }
    public bool Critical { get; }

    public X509ExtensionTemplate(Oid oid, IAsnValue? value, bool critical = false)
    {
        Oid = oid;
        Value = value;
        Critical = critical;
    }

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
