namespace OpenCertServer.Mcp.Tools;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Retrieve root and intermediate CA certificates.
///
/// Input: profileName (string, optional) - CA profile name
///        includeFullChain (bool, optional) - include rollover certificates in response
/// Output: Collection of CA certificates with metadata
/// </summary>
[McpServerToolType]
public class GetCaCertificatesTool
{
    [McpServerTool(Name = "get_ca_certificates", ReadOnly = true, Idempotent = true, Destructive = false)]
    [Description("Retrieve root/intermediate CA certificates and optional full chain.")]
    public static async Task<McpCaCertificatesResult> GetCaCertificates(
        ICertificateAuthority ca,
        [Description("CA profile name (optional, uses default if omitted)")] string? profileName = null,
        [Description("Include rollover/transition certificates")] bool includeFullChain = false,
        CancellationToken cancellationToken = default)
    {
        var certs = includeFullChain
            ? await ca.GetPublishedCertificates(profileName, cancellationToken).ConfigureAwait(false)
            : await ca.GetRootCertificates(profileName, cancellationToken).ConfigureAwait(false);

        var result = new List<McpCertificateItem>();

        foreach (var cert in certs)
        {
            result.Add(new McpCertificateItem
            {
                SerialNumber = GetSerialNumberString(cert),
                Subject = cert.Subject,
                Issuer = cert.Issuer,
                Thumbprint = cert.Thumbprint,
                NotBefore = cert.NotBefore,
                NotAfter = cert.NotAfter,
                PublicKeyAlgorithm = cert.PublicKey?.Oid?.Value ?? "unknown",
                PublicKeySize =
                    ((AsymmetricAlgorithm?)cert.GetRSAPublicKey() ?? cert.GetECDsaPublicKey())?.KeySize ?? 0,
                IsRevoked = false,
                RevocationReason = null,
                RevocationDate = null,
                Pem = cert.ExportCertificatePem()
            });
        }

        return new McpCaCertificatesResult
        {
            Profiles = [profileName ?? "(default)"],
            Certificates = result,
            Count = result.Count
        };
    }

    private static string GetSerialNumberString(X509Certificate2 cert)
    {
        // Use GetSerialNumberString() which returns big-endian hex matching the store's key format
        return cert.GetSerialNumberString();
    }

}