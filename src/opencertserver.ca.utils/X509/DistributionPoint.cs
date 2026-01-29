namespace OpenCertServer.Ca.Utils.X509;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

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
public class DistributionPoint : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DistributionPoint"/> class.
    /// </summary>
    /// <param name="distributionPointName">The optional distribution point name.</param>
    /// <param name="reasons">The optional revocation reasons</param>
    /// <param name="crlIssuer">The optional certificate issuer.</param>
    public DistributionPoint(
        DistributionPointName? distributionPointName = null,
        X509RevocationReason? reasons = null,
        GeneralNames? crlIssuer = null)
    {
        DistributionPointName = distributionPointName;
        Reasons = reasons;
        CrlIssuer = crlIssuer;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DistributionPoint"/> class.
    /// </summary>
    /// <param name="encoded">The raw DER encoded data.</param>
    public DistributionPoint(ReadOnlyMemory<byte> encoded)
        : this(new AsnReader(encoded.ToArray(), AsnEncodingRules.DER))
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="DistributionPoint"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read content from.</param>
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

    /// <summary>
    /// Gets the optional distribution point name.
    /// </summary>
    public DistributionPointName? DistributionPointName { get; }

    /// <summary>
    /// Gets the optional revocation reasons.
    /// </summary>
    public X509RevocationReason? Reasons { get; }

    /// <summary>
    /// Gets the optional certificate issuer.
    /// </summary>
    public GeneralNames? CrlIssuer { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag)
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
