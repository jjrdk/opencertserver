using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Defines the ResponseData structure as per RFC 6960.
/// </summary>
/// <code>
/// ResponseData ::= SEQUENCE {
///   version              [0] EXPLICIT Version DEFAULT v1,
///   responderID              ResponderID,
///   producedAt               GeneralizedTime,
///   responses                SEQUENCE OF SingleResponse,
///   responseExtensions   [1] EXPLICIT Extensions OPTIONAL
/// }
/// </code>
public class ResponseData : IAsnValue
{
    public ResponseData(
        TypeVersion version,
        IResponderId responderId,
        DateTimeOffset producedAt,
        IEnumerable<SingleResponse> responses)
    {
        Version = version;
        ResponderId = responderId;
        ProducedAt = producedAt;
        Responses = responses;
    }

    public ResponseData(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        {
            Version = (TypeVersion)(int)sequenceReader.ReadInteger(new Asn1Tag(TagClass.ContextSpecific, 0, true));
        }
        else
        {
            Version = TypeVersion.V1;
        }

        var responserIdTag = sequenceReader.PeekTag();
        ResponderId = responserIdTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1))
            ? new ResponderIdByName(new X509Name(sequenceReader))
            : new ResponderIdByKey(sequenceReader.ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, 2)));
        ProducedAt = sequenceReader.ReadGeneralizedTime();
        var responsesReader = sequenceReader.ReadSequence();
        var responses = new List<SingleResponse>();
        while (responsesReader.HasData)
        {
            responses.Add(new SingleResponse(responsesReader));
        }

        Responses = responses.AsReadOnly();
    }

    public TypeVersion Version { get; }

    public IResponderId ResponderId { get; }

    public DateTimeOffset ProducedAt { get; }

    public IEnumerable<SingleResponse> Responses { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        if (Version != TypeVersion.V1)
        {
            writer.WriteInteger((int)Version, new Asn1Tag(TagClass.ContextSpecific, 0, true));
        }

        ResponderId.Encode(writer);
        writer.WriteGeneralizedTime(ProducedAt);
        writer.PushSequence(new Asn1Tag(UniversalTagNumber.Sequence));
        foreach (var response in Responses)
        {
            response.Encode(writer);
        }

        writer.PopSequence(new Asn1Tag(UniversalTagNumber.Sequence));
        writer.PopSequence(tag);
    }
}
