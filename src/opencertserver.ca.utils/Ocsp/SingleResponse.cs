using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Defines the SingleResponse structure as per RFC 6960.
/// This structure represents the status of a single certificate in an OCSP response.
/// </summary>
/// <code>
/// SingleResponse ::= SEQUENCE {
///   certID                       CertID,
///   certStatus                   CertStatus,
///   thisUpdate                   GeneralizedTime,
///   nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
///   singleExtensions   [1]       EXPLICIT Extensions OPTIONAL
/// }
/// </code>
public class SingleResponse : IAsnValue
{
    public SingleResponse(
        CertId certId,
        (CertificateStatus, RevokedInfo?) certStatus,
        DateTimeOffset thisUpdate,
        DateTimeOffset? nextUpdate = null)
    {
        CertId = certId;
        CertStatus = certStatus.Item1;
        RevokedInfo = certStatus.Item2;
        ThisUpdate = thisUpdate;
        NextUpdate = nextUpdate;
    }

    public SingleResponse(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        CertId = new CertId(sequenceReader);
        var certStatusTag = sequenceReader.PeekTag();
        if (certStatusTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            CertStatus = CertificateStatus.Revoked;
            RevokedInfo = new RevokedInfo(sequenceReader, certStatusTag);
        }
        else if (certStatusTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
        {
            CertStatus = CertificateStatus.Unknown;
            sequenceReader.ReadNull(new Asn1Tag(TagClass.ContextSpecific, 2));
        }
        else
        {
            CertStatus = CertificateStatus.Good;
            sequenceReader.ReadNull();
        }

        ThisUpdate = sequenceReader.ReadGeneralizedTime();
        if (sequenceReader.HasData && sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        {
            NextUpdate = sequenceReader.ReadGeneralizedTime(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        }
    }

    public CertId CertId { get; }

    public CertificateStatus CertStatus { get; }

    public RevokedInfo? RevokedInfo { get; }

    public DateTimeOffset ThisUpdate { get; }

    public DateTimeOffset? NextUpdate { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        CertId.Encode(writer);
        switch (CertStatus)
        {
            case CertificateStatus.Good:
                writer.WriteNull();
                break;
            case CertificateStatus.Revoked:
                RevokedInfo!.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 1));
                break;
            case CertificateStatus.Unknown:
                writer.WriteNull(new Asn1Tag(TagClass.ContextSpecific, 2));
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(CertStatus), "Invalid certificate status");
        }

        writer.WriteGeneralizedTime(ThisUpdate);
        if (NextUpdate.HasValue)
        {
            writer.WriteGeneralizedTime(NextUpdate.Value, false, new Asn1Tag(TagClass.ContextSpecific, 0, true));
        }
        writer.PopSequence(tag);
    }
}
