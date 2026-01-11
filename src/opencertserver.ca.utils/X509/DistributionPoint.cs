using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the DistributionPoint class.
/// </summary>
/// <remarks>
/// DistributionPoint ::= Sequence {
///      distributionPoint [0] DistributionPointName OPTIONAL,
///      reasons           [1] ReasonFlags OPTIONAL,
///      cRLIssuer         [2] GeneralNames OPTIONAL
/// }
/// </remarks>
public class DistributionPoint : AsnValue
{
    public DistributionPoint(
        DistributionPointName? distributionPointName = null,
        X509RevocationReason? reasons = null,
        GeneralNames? crlIssuer = null)
    {
        DistributionPointName = distributionPointName;
        Reasons = reasons;
        CrlIssuer = crlIssuer;
    }

    public DistributionPoint(ReadOnlyMemory<byte> encoded)
        : this(new AsnReader(encoded.ToArray(), AsnEncodingRules.DER))
    {
    }

    public DistributionPoint(AsnReader reader)
    {
        var seq = reader.ReadSequence();

        while (seq.HasData)
        {
            var tag = seq.PeekTag();
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                DistributionPointName = new DistributionPointName(seq.ReadEncodedValue());
            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
            {
                Reasons = seq.ReadEnumeratedValue<X509RevocationReason>(tag);
            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                CrlIssuer = new GeneralNames(seq.ReadEncodedValue());
            }
        }
    }

    public DistributionPointName? DistributionPointName { get; }

    public X509RevocationReason? Reasons { get; }

    public GeneralNames? CrlIssuer { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag)
    {
        using (writer.PushSequence(tag))
        {
            DistributionPointName?.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));

            if (Reasons is not null)
            {
                writer.WriteEnumeratedValue(Reasons.Value, new Asn1Tag(TagClass.ContextSpecific, 1));
            }

            CrlIssuer?.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 2));
        }
    }
}
