namespace OpenCertServer.Mcp.Tools;

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Sign a Certificate Signing Request and return the signed certificate.
///
/// Input: csr (string, required) - PEM or Base64-encoded CSR
///        profileName (string, optional) - CA profile name
///        notBefore (string, optional) - ISO 8601 date/time
///        notAfter (string, optional) - ISO 8601 date/time
///        includePem (bool, optional) - Include PEM cert in response
/// Output: Signed certificate metadata + optionally PEM
/// </summary>
[McpServerToolType]
public class SignCertificateTool
{
    [McpServerTool(Name = "sign_certificate", ReadOnly = false, Idempotent = false, Destructive = true)]
    [Description("Sign a Certificate Signing Request (CSR) and return signed certificate metadata.")]
    public static async Task<McpCertificateItem> SignCertificate(
        ICertificateAuthority ca,
        [Description("PEM or Base64-encoded Certificate Signing Request")] string csr,
        [Description("CA profile name (optional, uses default if omitted)")] string? profileName = null,
        [Description("Certificate validity start (ISO 8601, optional)")] DateTimeOffset? notBefore = null,
        [Description("Certificate validity end (ISO 8601, optional)")] DateTimeOffset? notAfter = null,
        [Description("Include PEM-encoded cert and chain in response")] bool includePem = false,
        CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(csr))
        {
            throw new McpException("csr is required");
        }

        CertificateRequest request;
        try
        {
            // Support both PEM and base64 DER formats
            var normalized = csr.Trim();
            if (normalized.StartsWith("-----BEGIN CERTIFICATE REQUEST-----"))
            {
                // Strip PEM headers/footers and whitespace
                normalized = normalized
                    .Replace("-----BEGIN CERTIFICATE REQUEST-----", "")
                    .Replace("-----END CERTIFICATE REQUEST-----", "")
                    .Replace("\r", "")
                    .Replace("\n", "")
                    .Replace(" ", "");
            }
            else
            {
                normalized = normalized.NormalizeBase64();
            }

            var csrDer = Convert.FromBase64String(normalized);
            request = CertificateRequest.LoadSigningRequest(
                csrDer,
                HashAlgorithmName.SHA256,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
                RSASignaturePadding.Pss);
        }
        catch (Exception ex)
        {
            throw new McpException($"CSR could not be parsed: {ex.Message}");
        }

        var result = await ca.SignCertificateRequest(
            request,
            profileName,
            requestor: null,
            reenrollingFrom: null,
            notBefore,
            notAfter,
            cancellationToken).ConfigureAwait(false);

        if (result is SignCertificateResponse.Success success)
        {
            var pem = includePem ? success.Certificate.ExportCertificatePem() : null;
            var pemChain = includePem
                ? $"{success.Certificate.ExportCertificatePem()}\n{string.Join("\n", success.Issuers.Select(c => c.ExportCertificatePem()))}"
                : null;

            return new McpCertificateItem
            {
                SerialNumber = success.Certificate.GetSerialNumberString(),
                Subject = success.Certificate.Subject,
                Issuer = success.Certificate.Issuer,
                Thumbprint = success.Certificate.Thumbprint,
                NotBefore = success.Certificate.NotBefore,
                NotAfter = success.Certificate.NotAfter,
                PublicKeyAlgorithm = success.Certificate.PublicKey?.Oid?.Value ?? "unknown",
                PublicKeySize =
                    ((AsymmetricAlgorithm?)success.Certificate.GetRSAPublicKey()
                     ?? success.Certificate.GetECDsaPublicKey())?.KeySize ?? 0,
                IsRevoked = false,
                RevocationReason = null,
                RevocationDate = null,
                Pem = pem,
                PemChain = pemChain
            };
        }

        var error = (SignCertificateResponse.Error)result;
        throw new McpException($"Certificate signing failed: {string.Join("; ", error.Errors)}");
    }
}