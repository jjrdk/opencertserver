namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;
using System.Security.Cryptography;

public class AlgorithmIdentifier : IAsnValue
{
    public AlgorithmIdentifier(Oid algorithmOid, Oid? curveOid = null)
    {
        AlgorithmOid = algorithmOid;
        CurveOid = curveOid;
    }

    public AlgorithmIdentifier(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        var tag = sequenceReader.PeekTag();
        while (tag.HasSameClassAndValue(new Asn1Tag(UniversalTagNumber.Sequence)))
        {
            sequenceReader = sequenceReader.ReadSequence();
            tag = sequenceReader.PeekTag();
        }

        AlgorithmOid = sequenceReader.ReadObjectIdentifier().InitializeOid();
        switch (AlgorithmOid.Value)
        {
            case Oids.EcPublicKey:
                // Skip parameters for EC (should be named curve OID)
                CurveOid = sequenceReader.ReadObjectIdentifier().InitializeOid();
                break;
            default:
                // Skip parameters for others (should be NULL)
                sequenceReader.ReadNull();
                break;
        }

        sequenceReader.ThrowIfNotEmpty();
    }

    public Oid AlgorithmOid { get; }

    public Oid? CurveOid { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(AlgorithmOid.Value!);
            if (CurveOid?.Value != null)
            {
                writer.WriteObjectIdentifier(CurveOid.Value);
            }
            else
            {
                writer.WriteNull();
            }
        }
    }
}
