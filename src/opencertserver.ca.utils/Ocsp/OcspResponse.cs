using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Defines an OCSPResponse
/// </summary>
/// <code>
/// OCSPResponse ::= SEQUENCE {
///   responseStatus         OCSPResponseStatus,
///   responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL
/// }
///  </code>
public class OcspResponse : IAsnValue
{
    public OcspResponse(OcspResponseStatus status, OcspBasicResponse response)
    {
        ResponseStatus = status;
        var writer = new AsnWriter(AsnEncodingRules.DER);
        response.Encode(writer);
        var responseBytes = writer.Encode();
        ResponseBytes = new ResponseBytes(Oids.OcspBasicResponse.InitializeOid(), responseBytes);
    }

    public OcspResponse(OcspResponseStatus status, ResponseBytes? responseBytes = null)
    {
        ResponseStatus = status;
        ResponseBytes = responseBytes;
    }

    public OcspResponse(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        ResponseStatus = sequenceReader.ReadEnumeratedValue<OcspResponseStatus>();
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            ResponseBytes = new ResponseBytes(sequenceReader, sequenceReader.PeekTag());
        }

        sequenceReader.ThrowIfNotEmpty();
    }

    public OcspResponseStatus ResponseStatus { get; }

    public ResponseBytes? ResponseBytes { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteEnumeratedValue(ResponseStatus);
            ResponseBytes?.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 0));
        }
    }
}
