namespace OpenCertServer.Ca.Utils.X509Extensions;

using System.Formats.Asn1;
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
    public X509DeltaCrlIndicatorExtension(BigInteger crlNumber)
        : this(EncodeDerInteger(crlNumber), isCritical: true)
    {
    }

    /// <summary>
    /// Internal constructor used when loading from DER-encoded CRL (preserves encoded criticality).
    /// </summary>
    internal X509DeltaCrlIndicatorExtension(ReadOnlySpan<byte> derEncodedInteger, bool isCritical)
        : base(new Oid("2.5.29.27", "Delta CRL Indicator"), derEncodedInteger, isCritical)
    {
    }

    /// <summary>
    /// Gets the base CRL number by decoding the DER INTEGER from RawData.
    /// </summary>
    public BigInteger CrlNumber
    {
        get
        {
            var reader = new AsnReader(RawData, AsnEncodingRules.DER);
            return reader.ReadInteger();
        }
    }

    private static byte[] EncodeDerInteger(BigInteger value)
    {
        var writer = new AsnWriter(AsnEncodingRules.DER);
        writer.WriteInteger(value);
        return writer.Encode();
    }
}
