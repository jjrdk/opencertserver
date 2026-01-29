namespace OpenCertServer.Ca.Utils.X509.Templates;

using System.Formats.Asn1;
using System.Security.Cryptography;

/// <summary>
/// Defines the SubjectPublicKeyInfoTemplate ASN.1 structure.
/// </summary>
/// <code>
/// SubjectPublicKeyInfoTemplate{PUBLIC-KEY:IOSet} ::= SEQUENCE {
///    algorithm AlgorithmIdentifier{PUBLIC-KEY, {IOSet}},
///    subjectPublicKey BIT STRING OPTIONAL
/// }
/// </code>
public class SubjectPublicKeyInfoTemplate : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="SubjectPublicKeyInfoTemplate"/> class.
    /// </summary>
    /// <param name="algorithmOid">The algorithm <see cref="Oid"/>.</param>
    /// <param name="curveOid">The optional elliptic curve <see cref="Oid"/>.</param>
    /// <param name="publicKey">The subject public key.</param>
    public SubjectPublicKeyInfoTemplate(Oid algorithmOid, Oid? curveOid = null, byte[]? publicKey = null)
    {
        AlgorithmOid = algorithmOid;
        CurveOid = curveOid;
        PublicKey = publicKey;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="SubjectPublicKeyInfoTemplate"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
    /// <param name="expectedTag">The expected <see cref="Asn1Tag"/> for the content.</param>
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

    /// <summary>
    /// Gets the algorithm <see cref="Oid"/>.
    /// </summary>
    public Oid AlgorithmOid { get; }

    /// <summary>
    /// Gets the optional elliptic curve <see cref="Oid"/>.
    /// </summary>
    public Oid? CurveOid { get; }

    /// <summary>
    /// Gets the subject public key.
    /// </summary>
    public byte[]? PublicKey { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
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
