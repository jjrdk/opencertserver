namespace OpenCertServer.Ca.Utils.X509Extensions;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Defines an X.509 extension with raw encoded data.
/// </summary>
public class X509RawExtension : X509Extension
{
    /// <summary>
    /// Initializes a new instance of the <see cref="X509RawExtension"/> class.
    /// </summary>
    /// <param name="oid">The <see cref="Oid"/> for the content.</param>
    /// <param name="isCritical">Sets whether the extension is critical.</param>
    /// <param name="rawData">The raw DER encoded data.</param>
    public X509RawExtension(
        Oid oid,
        bool isCritical,
        ReadOnlySpan<byte> rawData)
        : base(oid, rawData, isCritical)
    {
    }
}
