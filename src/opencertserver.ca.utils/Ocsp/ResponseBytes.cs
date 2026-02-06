using System.Formats.Asn1;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

public class ResponseBytes : IAsnValue
{
    public ResponseBytes(Oid responseType, byte[] response)
    {
        ResponseType = responseType;
        Response = response;
    }

    public ResponseBytes(AsnReader reader, Asn1Tag? expectedTag = null)
    {
        var sequenceReader = reader.ReadSequence(expectedTag);
        ResponseType = sequenceReader.ReadObjectIdentifier().InitializeOid();
        Response = sequenceReader.ReadOctetString();
        sequenceReader.ThrowIfNotEmpty();
    }

    public Oid ResponseType { get; }

    public byte[] Response { get; }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(ResponseType.Value!);
            writer.WriteOctetString(Response);
        }
    }
}
