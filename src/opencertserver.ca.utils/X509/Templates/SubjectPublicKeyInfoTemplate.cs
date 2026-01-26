using System.Formats.Asn1;
using System.Security.Cryptography;

namespace OpenCertServer.Ca.Utils.X509.Templates;

public class SubjectPublicKeyInfoTemplate : AsnValue
{
    /*
    SubjectPublicKeyInfoTemplate{PUBLIC-KEY:IOSet} ::= SEQUENCE {
       algorithm AlgorithmIdentifier{PUBLIC-KEY, {IOSet}},
       subjectPublicKey BIT STRING OPTIONAL
    }
     */

    public SubjectPublicKeyInfoTemplate(Oid algorithm, byte[]? publicKey = null)
    {
        Algorithm = algorithm;
        PublicKey = publicKey;
    }

    public SubjectPublicKeyInfoTemplate(AsnReader reader, Asn1Tag? expectedTag = null)
    {
        var sequenceReader = reader.ReadSequence(expectedTag);
        Algorithm = new Oid(sequenceReader.ReadObjectIdentifier());
        if (reader.HasData)
        {
            PublicKey = sequenceReader.ReadBitString(out _);
        }
    }

    public Oid Algorithm { get; }
    public byte[]? PublicKey { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(Algorithm.Value!);
            if (PublicKey != null)
            {
                writer.WriteBitString(PublicKey.AsSpan());
            }
        }
    }
}
