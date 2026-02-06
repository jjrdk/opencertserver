using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Defines an OCSPRequest
/// </summary>
/// <code>
/// SEQUENCE {
///     tbsRequest                  TBSRequest,
///     optionalSignature   [0]     EXPLICIT Signature OPTIONAL
/// }
/// </code>
public class OcspRequest : IAsnValue
{
    public OcspRequest(TbsRequest tbsRequest, Signature? signature = null)
    {
        TbsRequest = tbsRequest;
        Signature = signature;
    }

    public OcspRequest(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        TbsRequest = new TbsRequest(sequenceReader);
        var tag = new Asn1Tag(TagClass.ContextSpecific, 0);
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(tag))
        {
            Signature = new Signature(sequenceReader, tag);
        }

        sequenceReader.ThrowIfNotEmpty();
    }

    public TbsRequest TbsRequest { get; }

    public Signature? Signature { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        TbsRequest.Encode(writer);
        Signature?.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));
        writer.PopSequence(tag);
    }
}
