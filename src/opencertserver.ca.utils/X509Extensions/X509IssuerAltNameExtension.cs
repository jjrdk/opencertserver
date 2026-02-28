using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils.X509Extensions;

using OpenCertServer.Ca.Utils;

/// <summary>
/// Defines the X509 Issuer Alternative Name Extension.
/// </summary>
public class X509IssuerAltNameExtension : X509Extension
{
    /// <summary>
    /// Initializes a new instance of the <see cref="X509IssuerAltNameExtension"/> class.
    /// </summary>
    /// <param name="rawData">The raw extension data.</param>
    /// <param name="isCritical">Indicates whether the extension is critical.</param>
    public X509IssuerAltNameExtension(ReadOnlySpan<byte> rawData, bool isCritical)
        : base(new Oid(Oids.IssuerAltName, "Issuer Alt Name"), rawData, isCritical)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="X509IssuerAltNameExtension"/> class.
    /// </summary>
    /// <param name="rawData">The raw extension data.</param>
    public X509IssuerAltNameExtension(ReadOnlySpan<byte> rawData)
        : base(new Oid(Oids.IssuerAltName, "Issuer Alt Name"), rawData, false)
    {
    }
}
