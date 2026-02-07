namespace OpenCertServer.Ca.Utils.X509Extensions;

using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

/// <summary>
/// Defines a certificate extension used in X.509 certificates.
/// </summary>
public class CertificateExtension : IAsnValue
{
    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateExtension"/> class.
    /// </summary>
    /// <param name="oid">The extension <see cref="Oid"/>.</param>
    /// <param name="reason">The optional <see cref="X509RevocationReason"/>.</param>
    /// <param name="certificateIssuer">The optional <see cref="X500DistinguishedName"/> of the certificate issuer.</param>
    /// <param name="invalidityDate">The optional invalidity as a <see cref="DateTimeOffset"/>.</param>
    /// <param name="isCritical">Sets whether the extension is critical.</param>
    public CertificateExtension(
        Oid oid,
        X509RevocationReason? reason,
        X500DistinguishedName? certificateIssuer,
        DateTimeOffset? invalidityDate,
        bool isCritical)
    {
        Oid = oid;
        CertificateIssuer = certificateIssuer;
        InvalidityDate = invalidityDate;
        IsCritical = isCritical;
        Reason = reason ?? X509RevocationReason.Unspecified;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="CertificateExtension"/> class.
    /// </summary>
    /// <param name="reader">The <see cref="AsnReader"/> to read the content.</param>
    /// <exception cref="CryptographicException">Thrown if an invalid revocation reason is found.</exception>
    public CertificateExtension(AsnReader reader)
    {
        var extension = reader.ReadSequence();
        var extnOid = extension.ReadObjectIdentifier().InitializeOid();
        X509RevocationReason? reason = null;
        X500DistinguishedName? certificateIssuer = null;
        DateTimeOffset? invalidityDate = null;
        var isCritical = false;

        if (extension.PeekTag().HasSameClassAndValue(Asn1Tag.Boolean))
        {
            isCritical = extension.ReadBoolean();
        }

        var extnValue = extension.ReadOctetString();

        switch (extnOid.Value)
        {
            case "2.5.29.29": // certificate issuer
            {
                var extnReader = new AsnReader(extnValue, AsnEncodingRules.DER);
                certificateIssuer = extnReader.ReadDistinguishedName();
                break;
            }
            case "2.5.29.24": // invalidity date
            {
                var extnReader = new AsnReader(extnValue, AsnEncodingRules.DER);
                invalidityDate = extnReader.ReadX509Time();
                break;
            }
            case "2.5.29.21": // reason code
            {
                var extnReader = new AsnReader(extnValue, AsnEncodingRules.DER);
                reason = extnReader.ReadEnumeratedValue<X509RevocationReason>();
                if (!Enum.IsDefined(typeof(X509RevocationReason), (int)reason))
                {
                    throw new CryptographicException("Invalid revocation reason code.");
                }

                break;
            }
        }

        Oid = extnOid;
        Reason = reason ?? X509RevocationReason.Unspecified;
        CertificateIssuer = certificateIssuer;
        InvalidityDate = invalidityDate;
        IsCritical = isCritical;
    }

    /// <summary>
    /// Gets the reason for certificate revocation.
    /// </summary>
    public X509RevocationReason Reason { get; }

    /// <summary>
    /// Gets the object identifier (OID) for the extension.
    /// </summary>
    public Oid Oid { get; }

    /// <summary>
    /// Gets the name of the certificate issuer.
    /// </summary>
    public X500DistinguishedName? CertificateIssuer { get; }

    /// <summary>
    /// Gets the optional invalidity date of the certificate.
    /// </summary>
    public DateTimeOffset? InvalidityDate { get; }

    /// <summary>
    /// Gets a value indicating whether the extension is critical.
    /// </summary>
    public bool IsCritical { get; }

    /// <inheritdoc/>
    public void Encode(AsnWriter writer, Asn1Tag? tag = null)
    {
        using (writer.PushSequence(tag))
        {
            writer.WriteObjectIdentifier(Oid.Value!);
            if (IsCritical)
            {
                writer.WriteBoolean(IsCritical);
            }

            var octetWriter = new AsnWriter(AsnEncodingRules.DER);
            switch (Oid.Value)
            {
                case "2.5.29.29": // certificate issuer
                    CertificateIssuer!.Encode(octetWriter);
                    break;
                case "2.5.29.24": // invalidity date
                    octetWriter.WriteUtcTime(InvalidityDate!.Value.ToUniversalTime());
                    break;
                case "2.5.29.21": // reason code
                    octetWriter.WriteEnumeratedValue(Reason);
                    break;
            }

            var octet = octetWriter.Encode();
            writer.WriteOctetString(octet);
        }
    }

}
