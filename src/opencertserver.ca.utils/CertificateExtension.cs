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
                    using (octetWriter.PushSequence())
                    {
                        foreach (var relativeDistinguishedName in
                            CertificateIssuer!.EnumerateRelativeDistinguishedNames())
                        {
                            using (octetWriter.PushSetOf())
                            {
                                using (octetWriter.PushSequence())
                                {
                                    octetWriter.WriteObjectIdentifier(relativeDistinguishedName.GetSingleElementType()
                                        .Value!);
                                    octetWriter.WriteCharacterString(
                                        UniversalTagNumber.PrintableString,
                                        relativeDistinguishedName.GetSingleElementValue()!);
                                }
                            }
                        }
                    }

                    break;
                case "2.5.29.24": // invalidity date
                    octetWriter.WriteUtcTime(InvalidityDate!.Value.ToUniversalTime());
                    break;
                case "2.5.29.21": // reason code
                {
                    octetWriter.WriteEnumeratedValue(Reason);
                    break;
                }
            }

            var octet = octetWriter.Encode();
            writer.WriteOctetString(octet);
        }
    }
}
