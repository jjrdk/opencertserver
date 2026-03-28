namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

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
    /// <summary>
    /// Initializes a new instance of the <see cref="OcspRequest"/> class.
    /// </summary>
    public OcspRequest(TbsRequest tbsRequest, Signature? signature = null)
    {
        TbsRequest = tbsRequest;
        Signature = signature;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="OcspRequest"/> class.
    /// </summary>
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

    /// <summary>
    /// Gets the to-be-signed request payload.
    /// </summary>
    public TbsRequest TbsRequest { get; }

    /// <summary>
    /// Gets the optional signature block for signed OCSP requests.
    /// </summary>
    public Signature? Signature { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        TbsRequest.Encode(writer);
        Signature?.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));
        writer.PopSequence(tag);
    }
}
