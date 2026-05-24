using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Mcp.Tools;

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
public static class SignCertificateTool
{
    public static async Task<McpToolResult> Handle(McpToolContext context)
    {
        var parameters = context.Parameters as IDictionary<string, object>;

        var csr = parameters?.TryGetValue("csr", out var csrObj) ?? false
            ? csrObj.ToString()
            : null;

        if (string.IsNullOrWhiteSpace(csr))
        {
            return McpToolResult.Fail("csr is required");
        }

        var profileName = parameters?.TryGetValue("profileName", out var profileObj) ?? false
            ? profileObj.ToString()
            : null;

        // Parse dates as DateTimeOffset to preserve timezone information
        var notBefore =
            parameters?.TryGetValue("notBefore", out var nbObj) == true &&
            DateTimeOffset.TryParse(nbObj.ToString(), System.Globalization.CultureInfo.InvariantCulture, 
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal, 
                out var nb)
                ? (DateTimeOffset?)nb
                : null;

        var notAfter =
            parameters?.TryGetValue("notAfter", out var naObj) == true &&
            DateTimeOffset.TryParse(naObj.ToString(), System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeUniversal | System.Globalization.DateTimeStyles.AdjustToUniversal,
                out var na)
                ? (DateTimeOffset?)na
                : null;

        var includePem = parameters?.TryGetValue("includePem", out var pemObj3) == true &&
            ParameterHelper.GetBoolean(pemObj3, false);

        var ca = context.GetService<ICertificateAuthority>();

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
            return McpToolResult.Fail($"CSR could not be parsed: {ex.Message}",
                (int)McpErrorCode.CertificateSigningFailed);
        }

        var result = await ca.SignCertificateRequest(
            request,
            profileName,
            requestor: null,
            reenrollingFrom: null,
            notBefore,
            notAfter,
            CancellationToken.None);

        if (result is SignCertificateResponse.Success success)
        {
            var pem = includePem ? success.Certificate.ExportCertificatePem() : null;
            var pemChain = includePem
                ? success.Certificate.ExportCertificatePem() + "\n" +
                string.Join("\n", success.Issuers.Select(c => c.ExportCertificatePem()))
                : null;

            return McpToolResult.Ok(new McpCertificateItem
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
            });
        }

        var error = (SignCertificateResponse.Error)result;
        return McpToolResult.Fail(
            $"Certificate signing failed: {string.Join("; ", error.Errors)}",
            (int)McpErrorCode.CertificateSigningFailed);
    }

    public static McpToolDefinition Create()
    {
        return new McpToolDefinition
        {
            Name = "sign_certificate",
            Description =
                "Sign a Certificate Signing Request (CSR) and return the signed certificate. Supports PEM or Base64-encoded CSR input, optional profile selection, and custom validity dates.",
            InputSchema = """
                          {
                                            "type": "object",
                                            "properties": {
                                                "csr": {
                                                    "type": "string",
                                                    "description": "PEM or Base64-encoded Certificate Signing Request"
                                                },
                                                "profileName": {
                                                    "type": "string",
                                                    "description": "CA profile name (optional, uses default if omitted)"
                                                },
                                                "notBefore": {
                                                    "type": "string",
                                                    "format": "date-time",
                                                    "description": "Certificate validity start (ISO 8601, optional)"
                                                },
                                                "notAfter": {
                                                    "type": "string",
                                                    "format": "date-time",
                                                    "description": "Certificate validity end (ISO 8601, optional)"
                                                },
                                                "includePem": {
                                                    "type": "boolean",
                                                    "description": "Include PEM-encoded cert and chain in response",
                                                    "default": false
                                                }
                                            },
                                            "required": ["csr"],
                                            "additionalProperties": false
                                        }
                          """,
            Handler = Handle
        };
    }
}
