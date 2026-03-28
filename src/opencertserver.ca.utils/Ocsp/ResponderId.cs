namespace OpenCertServer.Ca.Utils.Ocsp;

using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the ResponderID structure as per RFC 6960.
/// This is a placeholder and should be implemented according to the specification, which allows
/// for either a byName or byKey identifier.
/// </summary>
/// <code>
/// ResponderID ::= CHOICE {
///   byName               [1] Name,
///   byKey                [2] KeyHash
/// }
/// </code>
public interface IResponderId : IAsnValue
{
}

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
