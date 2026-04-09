namespace OpenCertServer.Ca.Utils.X509Extensions;

using System.Formats.Asn1;
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
    /// Called during deserialization: <paramref name="crlNumber"/> is the raw content of the
    /// extension's OCTET STRING, which is a DER-encoded INTEGER.
    /// </summary>
    /// <param name="crlNumber">The DER-encoded INTEGER bytes from the extension's extnValue OCTET STRING.</param>
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
        : this(EncodeDerInteger(crlNumber), isCritical)
    {
    }

    /// <summary>
    /// Gets the CRL number by decoding the DER INTEGER from RawData.
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
