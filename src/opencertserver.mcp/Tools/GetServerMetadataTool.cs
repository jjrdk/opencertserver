namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// Returns CA server metadata: CA name, distinguished name, supported profiles,
/// key types, signature algorithms, OCSP/CRL URLs, and EST endpoint URLs.
/// </summary>
public static class GetServerMetadataTool
{
    public static async Task<McpToolResult> Handle(McpToolContext context)
    {
        var options = context.GetService<IOptionsMonitor<McpServerOptions>>().CurrentValue;
        var caConfig = context.GetService<CaConfiguration>();
        var profiles = context.GetService<IStoreCaProfiles>();

        var profileList = new List<CaProfileInfo>();
        var caProfiles = await profiles
            .GetProfiles(CancellationToken.None)
            .ToListAsync(CancellationToken.None);

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

        var result = new McpServerMetadata
        {
            ServerName = options.ServerName,
            ServerVersion = options.ServerVersion,
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

        return McpToolResult.Ok(result);
    }

    public static McpToolDefinition Create()
    {
        return new McpToolDefinition
        {
            Name = "get_server_metadata",
            Description = "Get CA server metadata: CA profiles, distinguished names, supported key types, signature algorithms, OCSP/CRL URLs, and EST endpoint URLs.",
            InputSchema = "{\"type\": \"object\", \"properties\": {}, \"additionalProperties\": false}",
            Handler = Handle
        };
    }
}