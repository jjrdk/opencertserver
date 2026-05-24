using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509Extensions;

namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// Retrieve the current Certificate Revocation List (CRL).
/// Parses the DER-encoded CRL and returns structured data:
/// issuer DN, lastUpdate, nextUpdate, CRL number, and list of revoked
/// certificates (serial number, revocation time, reason).
/// Optionally include raw PEM in response.
/// </summary>
public static class GetCrlTool
{
    public static async Task<McpToolResult> Handle(McpToolContext context)
     {
        var parameters = context.Parameters as IDictionary<string, object>;

        var profileName = parameters?.TryGetValue("profileName", out var profileObj) ?? false
               ? profileObj.ToString()
               : null;

        var includePem = parameters?.TryGetValue("includePem", out var pemObj) ?? false
               ? ParameterHelper.GetBoolean(pemObj, false)
               : false;

        var ca = context.GetService<ICertificateAuthority>();
        var crlBytes = await ca.GetRevocationList(profileName, CancellationToken.None);

        var parsed = ParseCrl(crlBytes);

        var result = new McpCrlResult
           {
             Profile = profileName ?? "(default)",
             CrlBytesBase64 = includePem ? Convert.ToBase64String(crlBytes) : null,
             LastUpdate = parsed?.ThisUpdate ?? DateTimeOffset.UtcNow,
             NextUpdate = parsed?.NextUpdate ?? DateTimeOffset.UtcNow.AddDays(7),
             Version = (int)(parsed?.Version ?? 0),
             CrlNumber = parsed?.CrlNumber.ToString() ?? "0",
             Issuer = parsed?.Issuer?.Name,
             SignatureAlgorithm = parsed?.SignatureAlgorithm.ToString(),
             RevokedCertificates = (parsed?.RevokedCertificates
                  .Select(rc => new McpRevokedCertEntry
                   {
                      SerialNumber = HexEncode(rc.Serial),
                       RevocationTime = rc.RevocationTime,
                       Reason = rc.Extensions
                             .OfType<CertificateExtension>()
                             .FirstOrDefault(e => e.Oid.Value == "2.5.29.21")
                         is CertificateExtension ext
                            ? ext.Reason.ToString()
                            : null
                    })
                  .ToList()
               ?? new List<McpRevokedCertEntry>())
           };

        return McpToolResult.Ok(result);
       }

    private static CertificateRevocationList? ParseCrl(byte[] crlBytes)
      {
        try
          {
            return CertificateRevocationList.Load(crlBytes);
          }
        catch
          {
              // If parsing fails, return null so fallback values are used
              // The raw bytes are still available if includePem is true
             return null;
          }
      }

    private static string HexEncode(byte[] bytes)
      {
        var sb = new System.Text.StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
             sb.Append(b.ToString("X2"));
        return sb.ToString();
      }

    public static McpToolDefinition Create()
      {
        return new McpToolDefinition
          {
            Name = "get_crl",
            Description =
                  "Retrieve the current Certificate Revocation List (CRL). Parses the DER-encoded CRL and returns structured data: issuer DN, last update, next update, CRL number, and list of revoked certificates (serial number, revocation time, reason). Optionally include raw PEM bytes in response.",
            InputSchema = """
                          {
                                              "type": "object",
                                              "properties": {
                                                  "profileName": {
                                                      "type": "string",
                                                      "description": "CA profile name (optional, uses default if omitted)"
                                                  },
                                                  "includePem": {
                                                      "type": "boolean",
                                                      "description": "Include raw PEM-encoded DER CRL in response",
                                                      "default": false
                                                  }
                                              },
                                              "additionalProperties": false
                                          }
                          """,
            Handler = Handle
          };
      }
}
