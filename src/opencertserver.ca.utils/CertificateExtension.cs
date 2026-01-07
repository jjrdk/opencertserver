using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils;

public record CertificateExtension
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
}
