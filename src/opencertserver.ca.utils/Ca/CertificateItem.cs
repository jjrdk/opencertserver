namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Cryptography.X509Certificates;

public class CertificateItemInfo
{
    public required string SerialNumber { get; set; }
    public required string DistinguishedName { get; set; }
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }

    public bool IsRevoked
    {
        get { return RevocationReason != null; }
    }

    public X509RevocationReason? RevocationReason { get; set; }
    public DateTimeOffset? RevocationDate { get; set; }
    public required string Thumbprint { get; set; }
}

public class CertificateItem : CertificateItemInfo
{
    public required string PublicKeyPem { get; set; }

    public CertificateItemInfo AsInfo()
    {
        return new CertificateItemInfo
        {
            SerialNumber = SerialNumber,
            DistinguishedName = DistinguishedName,
            NotBefore = NotBefore,
            NotAfter = NotAfter,
            RevocationReason = RevocationReason,
            RevocationDate = RevocationDate,
            Thumbprint = Thumbprint
        };
    }

    public static CertificateItem FromX509Certificate2(X509Certificate2 cert)
    {
        return new CertificateItem
        {
            SerialNumber = cert.GetSerialNumberString(),
            DistinguishedName = cert.Subject,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            Thumbprint = cert.Thumbprint,
            PublicKeyPem = cert.ExportCertificatePem()
        };
    }
}
