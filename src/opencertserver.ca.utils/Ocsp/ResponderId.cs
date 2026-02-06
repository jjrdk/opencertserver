using System.Formats.Asn1;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils.Ocsp;

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

public class ResponderIdByName : IResponderId
{
    public X509Name Name { get; }

    public ResponderIdByName(X509Name name)
    {
        Name = name;
    }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        Name.Encode(writer, new Asn1Tag(TagClass.ContextSpecific, 1));
    }
}

public class ResponderIdByKey : IResponderId
{
    public byte[] KeyHash { get; }

    public ResponderIdByKey(byte[] keyHash)
    {
        KeyHash = keyHash;
    }

    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        writer.WriteOctetString(KeyHash, new Asn1Tag(TagClass.ContextSpecific, 2));
    }
}
