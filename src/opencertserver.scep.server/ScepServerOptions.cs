namespace OpenCertServer.Scep.Server;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Configuration of the SCEP server.
/// </summary>
public sealed class ScepServerOptions
{
    /// <summary>
    /// The registration authority certificate with its RSA private key. SCEP clients encrypt
    /// their request to it, and the server signs its responses with it. It must be RSA, even
    /// when the CA itself uses ECDSA: the SCEP envelope is defined for RSA key transport.
    /// </summary>
    public required X509Certificate2 RaCertificate { get; init; }

    /// <summary>
    /// The CA profile to issue from when the request does not name one in the path.
    /// </summary>
    public string? DefaultProfile { get; init; }
}
