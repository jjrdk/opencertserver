namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Represents a ResponderID identified by responder distinguished name.
/// </summary>
public class ResponderIdByName : IResponderId
{
    /// <summary>
    /// Gets the responder distinguished name.
    /// </summary>
    public X509Name Name { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ResponderIdByName"/> class.
    /// </summary>
    public ResponderIdByName(X509Name name)
    {
        Name = name;
    }

    /// <summary>
    /// Executes the Encode operation.
    /// </summary>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        Name.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 1));
    }
}