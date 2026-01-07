using System.Collections.ObjectModel;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils;

public record RevokedCertificate
{
    internal RevokedCertificate(
        byte[] serialNumber,
        DateTimeOffset revocationTime,
        params Span<CertificateExtension> extensions)
    {
        Serial = serialNumber;
        RevocationTime = revocationTime;
        Extensions = new ReadOnlyCollection<CertificateExtension>(extensions.ToArray());
    }

    public byte[] Serial { get; }
    public DateTimeOffset RevocationTime { get; }
    public IReadOnlyCollection<CertificateExtension> Extensions { get; }
}

public record CertificateExtension
{
    public CertificateExtension(
        string oid,
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

    public string Oid { get; }
    public X500DistinguishedName? CertificateIssuer { get; }
    public DateTimeOffset? InvalidityDate { get; }
    public bool IsCritical { get; }
}
