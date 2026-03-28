namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using System.Security.Cryptography;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Represents OCSP response bytes, including response type OID and encoded response payload.
/// </summary>
public class ResponseBytes : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ResponseBytes"/> class.
    /// </summary>
    public ResponseBytes(Oid responseType, byte[] response)
    {
        ResponseType = responseType;
        Response = response;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ResponseBytes"/> class.
    /// </summary>
    public ResponseBytes(AsnReader reader, Asn1Tag? expectedTag = null)
    {
        var sequenceReader = reader.ReadSequence(expectedTag);
        ResponseType = sequenceReader.ReadObjectIdentifier().InitializeOid();
        Response = sequenceReader.ReadOctetString();
        sequenceReader.ThrowIfNotEmpty();
    }

    /// <summary>
    /// Gets the response type object identifier.
    /// </summary>
    public Oid ResponseType { get; }

    /// <summary>
    /// Gets the encoded response payload bytes.
    /// </summary>
    public byte[] Response { get; }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(ResponseType.Value!);
            writer.WriteOctetString(Response);
        }
    }
}
