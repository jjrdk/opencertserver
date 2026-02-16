using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils.X509Extensions;

/// <summary>
/// Defines the X509 Delta CRL Indicator Extension
/// </summary>
public class X509IssuerAltNameExtension : X509Extension
{
    /// <summary>
    /// Initializes a new instance of the <see cref="X509IssuerAltNameExtension"/> class.
    /// </summary>
    /// <param name="rawData">The raw extension data.</param>
    public X509IssuerAltNameExtension(ReadOnlySpan<byte> rawData)
        : base(new Oid("2.5.29.18", "Issuer Alt Name"), rawData, false)
    {
    }
}
