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

    public SubjectPublicKeyInfoTemplate(Oid algorithmOid, Oid? curveOid = null, byte[]? publicKey = null)
    {
        AlgorithmOid = algorithmOid;
        CurveOid = curveOid;
        PublicKey = publicKey;
    }

    public SubjectPublicKeyInfoTemplate(AsnReader reader, Asn1Tag? expectedTag = null)
    {
        var sequenceReader = reader.ReadSequence(expectedTag);
        var algoReader = sequenceReader.ReadSequence();
        AlgorithmOid = algoReader.ReadObjectIdentifier().InitializeOid();
        switch (AlgorithmOid.Value)
        {
            case Oids.Rsa:
                // Skip parameters for RSA (should be NULL)
                algoReader.ReadNull();
                break;
            case Oids.EcPublicKey:
                // Skip parameters for EC (should be named curve OID)
                CurveOid = algoReader.ReadObjectIdentifier().InitializeOid();
                break;
        }
        if (sequenceReader.HasData)
        {
            PublicKey = sequenceReader.ReadBitString(out _);
        }
    }

    public Oid AlgorithmOid { get; }

    public Oid? CurveOid { get; }

    public byte[]? PublicKey { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            using (writer.PushSequence())
            {
                writer.WriteObjectIdentifier(AlgorithmOid.Value!);
                if (CurveOid?.Value != null)
                {
                    writer.WriteObjectIdentifier(CurveOid.Value);
                }
                else if (AlgorithmOid.Value == Oids.Rsa)
                {
                    writer.WriteNull();
                }
            }

            if (PublicKey != null)
            {
                writer.WriteBitString(PublicKey.AsSpan());
            }
        }
    }
}
