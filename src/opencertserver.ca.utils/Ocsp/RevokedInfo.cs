namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the RevokedInfo structure as per RFC 6960.
/// </summary>
/// <code>
/// RevokedInfo ::= SEQUENCE {
///   revocationTime              GeneralizedTime,
///   revocationReason    [0]     EXPLICIT CRLReason OPTIONAL
/// }
/// </code>
public class RevokedInfo : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RevokedInfo"/> class.
    /// </summary>
    public RevokedInfo(DateTimeOffset revocationTime, X509RevocationReason? revocationReason = null)
    {
        RevocationTime = revocationTime;
        RevocationReason = revocationReason;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="RevokedInfo"/> class.
    /// </summary>
    public RevokedInfo(AsnReader reader, Asn1Tag expectedTag)
    {
        var sequenceReader = reader.ReadSequence(expectedTag);
        RevocationTime = sequenceReader.ReadGeneralizedTime();
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        {
            RevocationReason =
                sequenceReader.ReadEnumeratedValue<X509RevocationReason>(new Asn1Tag(TagClass.ContextSpecific, 0,
                    true));
        }
    }

    /// <summary>
    /// Gets the revocation timestamp for the certificate.
    /// </summary>
    public DateTimeOffset RevocationTime { get; }

    /// <summary>
    /// Gets the optional revocation reason code.
    /// </summary>
    public X509RevocationReason? RevocationReason { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteGeneralizedTime(RevocationTime);
            if (RevocationReason.HasValue)
            {
                writer.WriteEnumeratedValue(RevocationReason.Value, new Asn1Tag(TagClass.ContextSpecific, 0, true));
            }
        }
    }
}
