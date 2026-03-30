namespace OpenCertServer.Ca.Utils.Pkcs7;

using System.Formats.Asn1;
using System.Numerics;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines the issuer and serial number for PKCS#7 content.
/// </summary>
/// <code>
/// IssuerAndSerialNumber ::= SEQUENCE {
///     issuer          Name,
///     serialNumber    CertificateSerialNumber
/// }
///
/// CertificateSerialNumber ::= INTEGER -- See RFC 5280
/// </code>
public class IssuerAndSerialNumber : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="IssuerAndSerialNumber"/> class with the specified issuer and serial number.
    /// </summary>
    /// <param name="reader">The ASN.1 reader to read the issuer and serial number from.</param>
    public IssuerAndSerialNumber(AsnReader reader)
    {
        var sequenceReader = reader.ReadSequence();
        Issuer = new X509Name(sequenceReader);
        SerialNumber = sequenceReader.ReadInteger();
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="IssuerAndSerialNumber"/> class with the specified issuer and serial number.
    /// </summary>
    /// <param name="issuer">The issuer name.</param>
    /// <param name="serialNumber">The serial number of the issuer.</param>
    public IssuerAndSerialNumber(X509Name issuer, BigInteger serialNumber)
    {
        Issuer = issuer;
        SerialNumber = serialNumber;
    }

    /// <summary>
    /// Gets the issuer name.
    /// </summary>
    public X509Name Issuer { get; }

    /// <summary>
    /// Gets the serial number of the issuer.
    /// </summary>
    public BigInteger SerialNumber { get; }

    /// <inheritdoc />
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            Issuer.Encode(writer);
            writer.WriteInteger(SerialNumber);
        }
    }
}
