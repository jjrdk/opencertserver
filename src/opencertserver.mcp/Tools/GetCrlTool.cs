namespace OpenCertServer.Mcp.Tools;

using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.X509Extensions;

/// <summary>
/// Retrieve the current Certificate Revocation List (CRL).
/// Parses the DER-encoded CRL and returns structured data:
/// issuer DN, lastUpdate, nextUpdate, CRL number, and list of revoked
/// certificates (serial number, revocation time, reason).
/// Optionally include raw PEM in response.
/// </summary>
[McpServerToolType]
public class GetCrlTool
{
    [McpServerTool(Name = "get_crl", ReadOnly = true, Idempotent = true, Destructive = false)]
    [Description("Retrieve the current CRL with parsed metadata and optional raw DER bytes.")]
    public static async Task<McpCrlResult> GetCrl(
        ICertificateAuthority ca,
        [Description("CA profile name (optional, uses default if omitted)")] string? profileName = null,
        [Description("Include raw DER CRL as base64 in response")] bool includePem = false,
        CancellationToken cancellationToken = default)
    {
        var crlBytes = await ca.GetRevocationList(profileName, cancellationToken).ConfigureAwait(false);

        var parsed = ParseCrl(crlBytes);

        return new McpCrlResult
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
}