using System.Formats.Asn1;
using System.Security.Cryptography;

namespace OpenCertServer.Ca.Utils.X509.Templates;

public class X509ExtensionTemplate : AsnValue
{
    public Oid Oid { get; }
    public AsnValue? Value { get; }
    public bool Critical { get; }

    public X509ExtensionTemplate(Oid oid, AsnValue? value, bool critical = false)
    {
        Oid = oid;
        Value = value;
        Critical = critical;
    }

    public static X509ExtensionTemplate Read(AsnReader reader)
    {
        var seqReader = reader.ReadSequence();
        var oid = seqReader.ReadObjectIdentifier().InitializeOid();
        var critical = false;
        AsnValue? value = null;
        if (seqReader.HasData && seqReader.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
        {
            critical = seqReader.ReadBoolean();
        }

        if (seqReader.HasData)
        {
            var octetString = seqReader.ReadOctetString();
            var valueReader = new AsnReader(octetString, AsnEncodingRules.DER);
            value = new AsnString(Asn1Tag.Null, valueReader.ReadCharacterString(UniversalTagNumber.UTF8String));
        }

        return new X509ExtensionTemplate(oid, value, critical);
    }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
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
