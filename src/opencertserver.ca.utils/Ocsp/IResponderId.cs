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