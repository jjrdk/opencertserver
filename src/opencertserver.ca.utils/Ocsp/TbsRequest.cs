using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Defines a TBSRequest
/// </summary>
/// <code>
/// SEQUENCE {
///     version             [0]     EXPLICIT Version DEFAULT v1,
///     requestorName       [1]     EXPLICIT GeneralName OPTIONAL,
///     requestList                 SEQUENCE OF Request,
///     requestExtensions   [2]     EXPLICIT Extensions OPTIONAL
/// }
/// </code>
public class TbsRequest : IAsnValue
{
    public TbsRequest(
        TypeVersion version = TypeVersion.V1,
        GeneralName? requestorName = null,
        IList<Request>? requestList = null,
        X509ExtensionCollection? requestExtensions = null)
    {
        Version = version;
        RequestorName = requestorName;
        RequestList = requestList ?? [];
        RequestExtensions = requestExtensions;
    }

    public TbsRequest(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        while (sequenceReader.HasData)
        {
            var tag = sequenceReader.PeekTag();
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            {
                Version = (TypeVersion)(int)sequenceReader.ReadInteger(new Asn1Tag(TagClass.ContextSpecific, 0));
            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
            {
                var encodedValue = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true));
                RequestorName = new GeneralName(encodedValue);
            }
            else if (tag.HasSameClassAndValue(Asn1Tag.Sequence))
            {
                var listReader = sequenceReader.ReadSequence();
                var requests = new List<Request>();
                while (listReader.HasData)
                {
                    requests.Add(new Request(listReader));
                }

                RequestList = requests;
            }
            else if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
            {
                var extReader = sequenceReader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
                RequestExtensions = [];
                while (extReader.HasData)
                {
                    var ext = extReader.DecodeExtension();
                    RequestExtensions.Add(ext);
                }

                extReader.ThrowIfNotEmpty();
            }
        }

        RequestList ??= [];
    }

    public TypeVersion Version { get; }

    public GeneralName? RequestorName { get; }

    public IList<Request> RequestList { get; }

    public X509ExtensionCollection? RequestExtensions { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            if (Version != TypeVersion.V1)
            {
                var integer = (int)Version;
                writer.WriteInteger(integer, new Asn1Tag(TagClass.ContextSpecific, 0, true));
            }

            if (RequestorName != null)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 1, true)))
                {
                    RequestorName?.Encode(writer);
                }
            }


            if (RequestList.Count > 0)
            {
                using (writer.PushSequence())
                {
                    foreach (var request in RequestList)
                    {
                        request.Encode(writer);
                    }
                }
            }

            if (RequestExtensions != null)
            {
                using (writer.PushSequence(new Asn1Tag(TagClass.ContextSpecific, 2, true)))
                {
                    foreach (var ext in RequestExtensions)
                    {
                        ext.Encode(writer);
                    }
                }
            }
        }
    }
}
