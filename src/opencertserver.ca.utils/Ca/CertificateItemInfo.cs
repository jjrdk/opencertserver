using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Ca.Utils.Ca;

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