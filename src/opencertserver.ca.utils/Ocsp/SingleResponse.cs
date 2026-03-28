namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

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
    /// <summary>
    /// Initializes a new instance of the <see cref="SingleResponse"/> class.
    /// </summary>
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

    /// <summary>
    /// Initializes a new instance of the <see cref="SingleResponse"/> class.
    /// </summary>
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

    /// <summary>
    /// Gets the certificate identifier this response applies to.
    /// </summary>
    public CertId CertId { get; }

    /// <summary>
    /// Gets the certificate status in this single response.
    /// </summary>
    public CertificateStatus CertStatus { get; }

    /// <summary>
    /// Gets revocation details when the certificate status is revoked.
    /// </summary>
    public RevokedInfo? RevokedInfo { get; }

    /// <summary>
    /// Gets the timestamp when this status was known to be correct.
    /// </summary>
    public DateTimeOffset ThisUpdate { get; }

    /// <summary>
    /// Gets the optional next update timestamp for this status.
    /// </summary>
    public DateTimeOffset? NextUpdate { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
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
