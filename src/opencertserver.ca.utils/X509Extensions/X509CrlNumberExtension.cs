namespace OpenCertServer.Ca.Utils.X509Extensions;

using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Defines the X509 CRL Number Extension
/// </summary>
public class X509CrlNumberExtension : X509Extension
{
    /// <summary>
    /// Initializes a new instance of the <see cref="X509CrlNumberExtension"/> class.
    /// </summary>
    /// <param name="crlNumber">The CRL number.</param>
    /// <param name="isCritical">Sets whether the extension is critical.</param>
    public X509CrlNumberExtension(ReadOnlySpan<byte> crlNumber, bool isCritical)
        : base(new Oid("2.5.29.20", "CRL Number"), crlNumber, isCritical)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509CrlNumberExtension"/> class.
    /// </summary>
    /// <param name="crlNumber">The CRL number.</param>
    /// <param name="isCritical">Sets whether the extension is critical.</param>
    public X509CrlNumberExtension(BigInteger crlNumber, bool isCritical)
        : this(crlNumber.ToByteArray(), isCritical)
    {
    }

    /// <summary>
    /// Gets the CRL number.
    /// </summary>
    public BigInteger CrlNumber
    {
        get { return new BigInteger(RawData); }
    }
}
