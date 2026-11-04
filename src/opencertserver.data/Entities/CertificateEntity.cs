using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Data.Entities;

/// <summary>
/// EF Core entity backing an issued certificate inventory record.
/// Mirrors <see cref="CertificateItemInfo"/> plus the public certificate PEM used to rebuild it on read.
/// </summary>
public class CertificateEntity
{
    /// <summary>Optional profile name, if the CA supports multiple profiles.</summary>
    public string? ProfileName { get; set; }

    /// <summary>Hex-encoded X.509 serial number, and the primary key.</summary>
    public required string SerialNumber { get; set; }

    /// <summary>Subject distinguished name.</summary>
    public required string DistinguishedName { get; set; }

    /// <summary>Issuer distinguished name, if the record captured it.</summary>
    public string? Issuer { get; set; }

    /// <summary>Certificate validity start.</summary>
    public DateTimeOffset NotBefore { get; set; }

    /// <summary>Certificate validity end.</summary>
    public DateTimeOffset NotAfter { get; set; }

    /// <summary>Certificate thumbprint, indexed for <c>GetCertificatesByThumbprint</c>.</summary>
    public required string Thumbprint { get; set; }

    /// <summary>Public certificate PEM, without private keys.</summary>
    public required string PublicKeyPem { get; set; }

    /// <summary>Revocation reason as an <c>int</c> (cast from <c>X509RevocationReason</c>), or null when not revoked.</summary>
    public int? RevocationReason { get; set; }

    /// <summary>When the certificate was revoked, or null when not revoked.</summary>
    public DateTimeOffset? RevocationDate { get; set; }
}
