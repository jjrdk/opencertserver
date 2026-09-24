namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// Returns CA server metadata: CA name, distinguished name, supported profiles,
/// key types, signature algorithms, OCSP/CRL URLs, and EST endpoint URLs.
/// </summary>
[McpServerToolType]
public class GetServerMetadataTool
{
    [McpServerTool(Name = "get_server_metadata", ReadOnly = true, Idempotent = true, Destructive = false)]
    [Description("Get CA server metadata including profiles, URLs, supported keys, and EST endpoints.")]
    public static async Task<McpServerMetadata> GetServerMetadata(
        CaConfiguration caConfig,
        IStoreCaProfiles profiles,
        IOptions<McpServerOptions> options,
        CancellationToken cancellationToken)
    {
        var mcpOptions = options.Value;

        var profileList = new List<CaProfileInfo>();
        var caProfiles = await profiles
            .GetProfiles(cancellationToken)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

        foreach (var profile in caProfiles)
        {
            profileList.Add(new CaProfileInfo
            {
                Name = profile.Name,
                CertificateChain = profile
                    .CertificateChain
                    .Select(c => c.ExportCertificatePem())
                    .ToList(),
                HasPrivateKey = profile.PrivateKey != null,
                CertificateValidityDays = profile.CertificateValidity.TotalDays,
                HasOcspSigningKey = profile.OcspSigningKey != null,
                OcspFreshnessWindow = profile.OcspFreshnessWindow.ToString()
            });
        }

        return new McpServerMetadata
        {
            ServerName = mcpOptions.ServerName,
            ServerVersion = mcpOptions.ServerVersion,
            CaProfiles = profileList,
            OcspUrls = caConfig.OcspUrls,
            CrlUrls = caConfig.CrlUrls,
            CaIssuersUrls = caConfig.CaIssuersUrls,
            EstEndpoints = new EstEndpoints
            {
                CaBundle = "/.well-known/est/cacerts",
                SimpleEnroll = "/.well-known/est/simpleenroll",
                SimpleReenroll = "/.well-known/est/simplereenroll",
                Pkipath = "/.well-known/est/pkipath"
            },
            SupportedKeyTypes = ["RSA", "ECDSA"],
            SupportedSignatureAlgorithms =
            [
                "SHA256withRSA", "SHA384withRSA", "SHA512withRSA",
                "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"
            ],
            MaxCsrKeySize = 4096,
            MinCsrKeySize = 2048
        };
    }
}