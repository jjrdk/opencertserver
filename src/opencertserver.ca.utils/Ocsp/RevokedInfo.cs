using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

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
    public RevokedInfo(DateTimeOffset revocationTime, X509RevocationReason? revocationReason = null)
    {
        RevocationTime = revocationTime;
        RevocationReason = revocationReason;
    }

    public RevokedInfo(AsnReader reader, Asn1Tag expectedTag)
    {
        var sequenceReader = reader.ReadSequence(expectedTag);
        RevocationTime = sequenceReader.ReadUtcTime();
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        {
            RevocationReason =
                sequenceReader.ReadEnumeratedValue<X509RevocationReason>(new Asn1Tag(TagClass.ContextSpecific, 0,
                    true));
        }
    }

    public DateTimeOffset RevocationTime { get; }

    public X509RevocationReason? RevocationReason { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteUtcTime(RevocationTime);
            if (RevocationReason.HasValue)
            {
                writer.WriteEnumeratedValue(RevocationReason.Value, new Asn1Tag(TagClass.ContextSpecific, 0, true));
            }
        }
    }
}
