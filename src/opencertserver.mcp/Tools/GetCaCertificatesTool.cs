using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// Retrieve root and intermediate CA certificates.
///
/// Input: profileName (string, optional) - CA profile name
///        includeFullChain (bool, optional) - include rollover certificates in response
/// Output: Collection of CA certificates with metadata
/// </summary>
public static class GetCaCertificatesTool
{
    public static async Task<McpToolResult> Handle(McpToolContext context)
    {
        var parameters = context.Parameters as IDictionary<string, object>;

        var profileName = parameters?.TryGetValue("profileName", out var profileObj) ?? false
            ? profileObj.ToString()
            : null;

        var includeFullChain = parameters?.TryGetValue("includeFullChain", out var chainObj) ?? false
            ? bool.TryParse(chainObj.ToString(), out var chain) && chain
            : false;

        var ca = context.GetService<ICertificateAuthority>();

        var certs = includeFullChain
            ? await ca.GetPublishedCertificates(profileName, CancellationToken.None)
            : await ca.GetRootCertificates(profileName, CancellationToken.None);

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

        return McpToolResult.Ok(new McpCaCertificatesResult
        {
            Profiles = [profileName ?? "(default)"],
            Certificates = result,
            Count = result.Count
        });
    }

    private static string GetSerialNumberString(X509Certificate2 cert)
    {
        // Use GetSerialNumberString() which returns big-endian hex matching the store's key format
        return cert.GetSerialNumberString();
    }

    public static McpToolDefinition Create()
    {
        return new McpToolDefinition
        {
            Name = "get_ca_certificates",
            Description =
                "Retrieve root and intermediate CA certificates. Optionally include rollover certificates from the published bundle. Returns certificate metadata and optionally PEM-encoded certificates.",
            InputSchema = @"{
                ""type"": ""object"",
                ""properties"": {
                    ""profileName"": {
                        ""type"": ""string"",
                        ""description"": ""CA profile name (optional, uses default if omitted)""
                    },
                    ""includeFullChain"": {
                        ""type"": ""boolean"",
                        ""description"": ""Include rollover/transition certificates"",
                        ""default"": false
                    }
                },
                ""additionalProperties"": false
            }",
            Handler = Handle
        };
    }
}
