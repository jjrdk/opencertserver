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
    public OcspRequest(TbsRequest tbsRequest, Signature? optionalSignature = null)
    {
        TbsRequest = tbsRequest;
        OptionalSignature = optionalSignature;
    }

    public OcspRequest(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        TbsRequest = new TbsRequest(sequenceReader);
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            var sigReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            OptionalSignature = new Signature(reader);
            sigReader.ThrowIfNotEmpty();
        }

        sequenceReader.ThrowIfNotEmpty();
    }

    public TbsRequest TbsRequest { get; }

    public Signature? OptionalSignature { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        TbsRequest.Encode(writer);
        OptionalSignature?.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));
        writer.PopSequence(tag);
    }
}
