namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using X509;

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
    /// <summary>
    /// Initializes a new instance of the <see cref="OcspResponse"/> class.
    /// </summary>
    public OcspResponse(OcspResponseStatus status, OcspBasicResponse response)
    {
        ResponseStatus = status;
        var writer = new AsnWriter(AsnEncodingRules.DER);
        response.Encode(writer);
        var responseBytes = writer.Encode();
        ResponseBytes = new ResponseBytes(Oids.OcspBasicResponse.InitializeOid(Oids.OcspBasicResponseFriendlyName),
            responseBytes);
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="OcspResponse"/> class.
    /// </summary>
    public OcspResponse(OcspResponseStatus status, ResponseBytes? responseBytes = null)
    {
        ResponseStatus = status;
        ResponseBytes = responseBytes;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="OcspResponse"/> class.
    /// </summary>
    public OcspResponse(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        ResponseStatus = sequenceReader.ReadEnumeratedValue<OcspResponseStatus>();
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
        {
            // responseBytes [0] EXPLICIT ResponseBytes (RFC 6960 4.2.1, EXPLICIT TAGS module).
            var explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0));
            ResponseBytes = new ResponseBytes(explicitReader);
            explicitReader.ThrowIfNotEmpty();
        }

        sequenceReader.ThrowIfNotEmpty();
    }

    /// <summary>
    /// Gets the OCSP response status value.
    /// </summary>
    public OcspResponseStatus ResponseStatus { get; }

    /// <summary>
    /// Gets the optional OCSP response bytes payload.
    /// </summary>
    public ResponseBytes? ResponseBytes { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteEnumeratedValue(ResponseStatus);
            if (ResponseBytes != null)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0)))
                {
                    ResponseBytes.Encode(writer);
                }
            }
        }
    }
}
