namespace OpenCertServer.Ca.Utils.X509Extensions;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Defines the X509 Freshest CRL Extension.
/// </summary>
public class X509FreshestCrlExtension : X509Extension
{
    /// <summary>
    /// Initializes a new instance of the <see cref="X509FreshestCrlExtension"/> class.
    /// </summary>
    /// <param name="freshestCrl">The freshest CRL location.</param>
    /// <param name="isCritical">Sets whether the extension is critical.</param>
    public X509FreshestCrlExtension(ReadOnlySpan<byte> freshestCrl, bool isCritical)
        : base(new Oid("2.5.29.46"), freshestCrl, isCritical)
    {
    }
}
