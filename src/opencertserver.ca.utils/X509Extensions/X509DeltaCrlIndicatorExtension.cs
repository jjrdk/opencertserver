namespace OpenCertServer.Ca.Utils.X509Extensions;

using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Defines the X509 Delta CRL Indicator Extension
/// </summary>
public class X509DeltaCrlIndicatorExtension : X509Extension
{
    /// <summary>
    /// Initializes a new instance of the <see cref="X509DeltaCrlIndicatorExtension"/> class.
    /// </summary>
    /// <param name="crlNumber">The CRL number.</param>
    /// <param name="isCritical">Sets whether the extension is critical.</param>
    public X509DeltaCrlIndicatorExtension(ReadOnlySpan<byte> crlNumber, bool isCritical)
        : base(new Oid("2.5.29.27", "Delta CRL Indicator"), crlNumber, isCritical)
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
