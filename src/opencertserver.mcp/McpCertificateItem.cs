using System.Security.Cryptography;

namespace OpenCertServer.Mcp;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Represents a single certificate record returned by MCP tools.
/// Plain POC for JSON serialization -- no private key material is exposed.
/// </summary>
public class McpCertificateItem
{
    /// <summary>Certificate serial number (hex string).</summary>
    public required string SerialNumber { get; set; }

    /// <summary>Subject distinguished name.</summary>
    public required string Subject { get; set; }

    /// <summary>Issuer distinguished name.</summary>
    public required string Issuer { get; set; }

    /// <summary>Certificate thumbprint (SHA-1 hex string).</summary>
    public required string Thumbprint { get; set; }

    /// <summary>Not-before validity date (UTC).</summary>
    public DateTime NotBefore { get; set; }

    /// <summary>Not-after validity date (UTC).</summary>
    public DateTime NotAfter { get; set; }

    /// <summary>
    /// Public key algorithm OID string.
    /// For RSA: "1.2.840.113549.1.1.1".
    /// For ECDSA: "1.2.840.10045.2.1".
    /// </summary>
    public required string PublicKeyAlgorithm { get; set; }

    /// <summary>Public key size in bits (e.g. 2048, 3072, 256, 384, 521).</summary>
    public required int PublicKeySize { get; set; }

    /// <summary>Whether the certificate is currently revoked.</summary>
    public bool IsRevoked { get; set; }

    /// <summary>Revocation reason if revoked, or null.</summary>
    public X509RevocationReason? RevocationReason { get; set; }

    /// <summary>Revocation date if revoked, or null.</summary>
    public DateTimeOffset? RevocationDate { get; set; }

    /// <summary>
    /// The full certificate PEM if requested via the "includePem" tool parameter.
    /// </summary>
    public string? Pem { get; set; }

    /// <summary>
    /// The certificate chain PEM (intermediate + root) if requested.
    /// </summary>
    public string? PemChain { get; set; }

    /// <summary>
    /// Build a McpCertificateItem from a X509Certificate2, optionally including PEM.
    /// </summary>
    public static McpCertificateItem FromX509Certificate2(
        X509Certificate2 cert,
        CertificateItemInfo? info = null,
        string? pem = null,
        string? pemChain = null)
    {
        return new McpCertificateItem
        {
            SerialNumber = GetSerialNumberString(cert),
            Subject = cert.Subject,
            Issuer = cert.Issuer,
            Thumbprint = cert.Thumbprint,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            PublicKeyAlgorithm = cert.PublicKey.Oid.Value ?? "unknown",
            PublicKeySize = ((AsymmetricAlgorithm?)cert.GetRSAPublicKey() ?? cert.GetECDsaPublicKey())?.KeySize ?? 0,
            IsRevoked = info?.RevocationReason != null,
            RevocationReason = info?.RevocationReason,
            RevocationDate = info?.RevocationDate,
            Pem = pem,
            PemChain = pemChain
        };
    }

    private static string GetSerialNumberString(X509Certificate2 cert)
    {
        var bytes = cert.GetSerialNumber();
        var sb = new System.Text.StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
        {
            sb.Append(b.ToString("X2"));
        }

        return sb.ToString();
    }
}
