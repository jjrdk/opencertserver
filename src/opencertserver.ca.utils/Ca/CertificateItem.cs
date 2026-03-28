namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Represents certificate metadata used for inventory and revocation list responses.
/// </summary>
public class CertificateItemInfo
{
    /// <summary>
    /// Gets or sets the certificate serial number.
    /// </summary>
    public required string SerialNumber { get; set; }
    /// <summary>
    /// Gets or sets the subject distinguished name.
    /// </summary>
    public required string DistinguishedName { get; set; }
    /// <summary>
    /// Gets or sets the certificate validity start time.
    /// </summary>
    public DateTime NotBefore { get; set; }
    /// <summary>
    /// Gets or sets the certificate validity end time.
    /// </summary>
    public DateTime NotAfter { get; set; }

    /// <summary>
    /// Represents the IsRevoked.
    /// </summary>
    public bool IsRevoked
    {
        get { return RevocationReason != null; }
    }

    /// <summary>
    /// Gets or sets the revocation reason when the certificate is revoked.
    /// </summary>
    public X509RevocationReason? RevocationReason { get; set; }
    /// <summary>
    /// Gets or sets the revocation timestamp when the certificate is revoked.
    /// </summary>
    public DateTimeOffset? RevocationDate { get; set; }
    /// <summary>
    /// Gets or sets the certificate thumbprint.
    /// </summary>
    public required string Thumbprint { get; set; }
}

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
