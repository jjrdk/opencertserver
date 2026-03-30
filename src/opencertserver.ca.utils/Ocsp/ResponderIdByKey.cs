using System.Formats.Asn1;

namespace OpenCertServer.Ca.Utils.Ocsp;

/// <summary>
/// Represents a ResponderID identified by responder key hash.
/// </summary>
public class ResponderIdByKey : IResponderId
{
    /// <summary>
    /// Gets the responder key hash.
    /// </summary>
    public byte[] KeyHash { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ResponderIdByKey"/> class.
    /// </summary>
    public ResponderIdByKey(byte[] keyHash)
    {
        KeyHash = keyHash;
    }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.WriteOctetString(KeyHash, new Asn1Tag(TagClass.ContextSpecific, 2));
    }
}