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
    /// RFC 5280 §5.2.4 requires this extension to always be marked critical.
    /// </summary>
    /// <param name="crlNumber">The base CRL number this delta supplements.</param>
    public X509DeltaCrlIndicatorExtension(ReadOnlySpan<byte> crlNumber)
        : base(new Oid("2.5.29.27", "Delta CRL Indicator"), crlNumber, critical: true)
    {
    }

    /// <summary>
    /// Internal constructor used when loading from DER-encoded CRL (preserves encoded criticality).
    /// </summary>
    internal X509DeltaCrlIndicatorExtension(ReadOnlySpan<byte> crlNumber, bool isCritical)
        : base(new Oid("2.5.29.27", "Delta CRL Indicator"), crlNumber, isCritical)
    {
    }

    /// <summary>
    /// Gets the base CRL number.
    /// </summary>
    public BigInteger CrlNumber
    {
        get { return new BigInteger(RawData, isUnsigned: true, isBigEndian: true); }
    }
}
