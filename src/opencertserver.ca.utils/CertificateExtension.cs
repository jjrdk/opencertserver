using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils.X509;

namespace OpenCertServer.Ca.Utils;

public class CertificateExtension : AsnValue
{
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

    public X509RevocationReason Reason { get; set; }

    public Oid Oid { get; }
    public X500DistinguishedName? CertificateIssuer { get; }
    public DateTimeOffset? InvalidityDate { get; }
    public bool IsCritical { get; }

    public override void Encode(AsnWriter writer, Asn1Tag? tag = null)
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

    public static CertificateExtension Decode(AsnReader extensions)
    {
        var extension = extensions.ReadSequence();
        var extnOid = new Oid(extension.ReadObjectIdentifier());
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

        var certificateExtension = new CertificateExtension(
            extnOid,
            reason,
            certificateIssuer,
            invalidityDate,
            isCritical);
        return certificateExtension;
    }

}
