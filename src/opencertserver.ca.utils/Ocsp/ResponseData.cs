namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using X509;

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
    /// <summary>
    /// Initializes a new instance of the <see cref="ResponseData"/> class.
    /// </summary>
    public ResponseData(
        TypeVersion version,
        IResponderId responderId,
        DateTimeOffset producedAt,
        IEnumerable<SingleResponse> responses,
        X509ExtensionCollection? responseExtensions = null)
    {
        Version = version;
        ResponderId = responderId;
        ProducedAt = producedAt;
        Responses = responses.ToArray().AsReadOnly();
        ResponseExtensions = responseExtensions;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ResponseData"/> class.
    /// </summary>
    public ResponseData(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
        {
            // version [0] EXPLICIT Version DEFAULT v1
            var versionReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true));
            Version = (TypeVersion)(int)versionReader.ReadInteger();
            versionReader.ThrowIfNotEmpty();
        }
        else
        {
            Version = TypeVersion.V1;
        }

        // ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash } - both EXPLICIT.
        var responderIdTag = sequenceReader.PeekTag();
        var responderIdReader = sequenceReader.ReadSequence(responderIdTag);
        ResponderId = responderIdTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1))
            ? new ResponderIdByName(new X509Name(responderIdReader))
            : responderIdTag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2))
                ? new ResponderIdByKey(responderIdReader.ReadOctetString())
                : throw new AsnContentException("Unexpected ResponderID tag " + responderIdTag);
        responderIdReader.ThrowIfNotEmpty();
        ProducedAt = sequenceReader.ReadGeneralizedTime();
        var responsesReader = sequenceReader.ReadSequence();
        var responses = new List<SingleResponse>();
        while (responsesReader.HasData)
        {
            responses.Add(new SingleResponse(responsesReader));
        }

        Responses = responses.AsReadOnly();

        if (sequenceReader.HasData &&
            sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
        {
            // responseExtensions [1] EXPLICIT Extensions
            var explicitReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
            var extReader = explicitReader.ReadSequence();
            explicitReader.ThrowIfNotEmpty();
            ResponseExtensions = [];
            while (extReader.HasData)
            {
                ResponseExtensions.Add(extReader.DecodeExtension());
            }
        }
    }

    /// <summary>
    /// Gets the response data version.
    /// </summary>
    public TypeVersion Version { get; }

    /// <summary>
    /// Gets the responder identifier.
    /// </summary>
    public IResponderId ResponderId { get; }

    /// <summary>
    /// Gets the production timestamp for this response data.
    /// </summary>
    public DateTimeOffset ProducedAt { get; }

    /// <summary>
    /// Gets the collection of single responses contained in this response.
    /// </summary>
    public IReadOnlyCollection<SingleResponse> Responses { get; }

    /// <summary>
    /// Gets the optional response-level extensions.
    /// </summary>
    public X509ExtensionCollection? ResponseExtensions { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.PushSequence(tag);
        if (Version != TypeVersion.V1)
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
            {
                writer.WriteInteger((int)Version);
            }
        }

        ResponderId.Encode(writer);
        writer.WriteGeneralizedTime(ProducedAt);
        writer.PushSequence(new Asn1Tag(UniversalTagNumber.Sequence));
        foreach (var response in Responses)
        {
            response.Encode(writer);
        }

        writer.PopSequence(new Asn1Tag(UniversalTagNumber.Sequence));

        if (ResponseExtensions is { Count: > 0 })
        {
            using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            using (writer.PushSequence())
            {
                foreach (var ext in ResponseExtensions)
                {
                    ext.Encode(writer);
                }
            }
        }

        writer.PopSequence(tag);
    }
}
