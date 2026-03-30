namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Represents a stored certificate record including public key PEM material.
/// </summary>
public class CertificateItem : CertificateItemInfo
{
    /// <summary>
    /// Gets or sets the certificate PEM-encoded public data.
    /// </summary>
    public required string PublicKeyPem { get; set; }

    /// <summary>
    /// Executes the AsInfo operation.
    /// </summary>
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

    /// <summary>
    /// Executes the FromX509Certificate2 operation.
    /// </summary>
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
