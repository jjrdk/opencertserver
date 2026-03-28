namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;
using System.Security.Cryptography;

/// <summary>
/// Represents an ASN.1 AlgorithmIdentifier value used in X.509 structures.
/// </summary>
public class AlgorithmIdentifier : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AlgorithmIdentifier"/> class.
    /// </summary>
    public AlgorithmIdentifier(Oid algorithmOid, Oid? curveOid = null)
    {
        AlgorithmOid = algorithmOid;
        CurveOid = curveOid;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="AlgorithmIdentifier"/> class.
    /// </summary>
    public AlgorithmIdentifier(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();

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

    /// <summary>
    /// Gets the algorithm object identifier.
    /// </summary>
    public Oid AlgorithmOid { get; }

    /// <summary>
    /// Gets the elliptic curve object identifier when the algorithm uses EC parameters.
    /// </summary>
    public Oid? CurveOid { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        writer.WriteObjectIdentifier(AlgorithmOid.Value!);
        if (CurveOid?.Value != null)
        {
            writer.WriteObjectIdentifier(CurveOid.Value);
        }
        else
        {
            writer.WriteNull();
        }

        writer.PopSequence(tag);
    }
}
