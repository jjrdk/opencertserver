namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// List all certificates in the CA store with pagination.
///
/// Input: page (int, default 0), pageSize (int, default 100, max 500)
/// Output: McpCertificateSearchResult with page of certificate metadata
/// </summary>
public static class ListCertificatesTool
{
    public static async Task<McpToolResult> ListCertificatesAsync(McpToolContext context)
    {
        var parameters = context.Parameters as IDictionary<string, object>;

        var pageObj2 = parameters?.TryGetValue("page", out var pageObj) ?? false ? pageObj : null;
        var page = pageObj2 != null ? Convert.ToInt32(pageObj2) : 0;
        var pageSizeObj2 = parameters?.TryGetValue("pageSize", out var pageSizeObj) ?? false ? pageSizeObj : null;
        var pageSize = pageSizeObj2 != null ? Convert.ToInt32(pageSizeObj2) : 100;

        if (pageSize is < 1 or > 500)
        {
            return McpToolResult.Fail("pageSize must be between 1 and 500");
        }

        var store = context.GetService<IStoreCertificates>();
        var inv = store.GetInventory(page, pageSize, CancellationToken.None);
        var items = await inv.ToListAsync(CancellationToken.None);

        // Estimate total count: if we got fewer items than pageSize, this is the last page.
        // For an accurate total, a dedicated COUNT query would be needed from a persistent store.
        var totalCount = (long)(page + 1) * pageSize;
        if (items.Count < pageSize)
        {
            totalCount = page * pageSize + items.Count;
        }

        var result = new McpCertificateSearchResult
         {
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount,
            Items = items.Select(info => new McpCertificateItem
            {
                SerialNumber = info.SerialNumber,
                Subject = info.DistinguishedName,
                Issuer = info.DistinguishedName,
                Thumbprint = info.Thumbprint,
                NotBefore = info.NotBefore,
                NotAfter = info.NotAfter,
                PublicKeyAlgorithm = "unknown",
                PublicKeySize = 0,
                IsRevoked = info.IsRevoked,
                RevocationReason = info.RevocationReason,
                RevocationDate = info.RevocationDate
            }).ToList()
        };

        return McpToolResult.Ok(result);
    }

    public static McpToolDefinition Create()
    {
        return new McpToolDefinition
        {
            Name = "list_certificates",
            Description = "List issued certificates with pagination. Returns serial number, subject, issuer, validity dates, thumbprint, and revocation status.",
            InputSchema = @"{
                ""type"": ""object"",
                ""properties"": {
                    ""page"": {
                        ""type"": ""integer"",
                        ""description"": ""Zero-based page index"",
                        ""default"": 0
                    },
                    ""pageSize"": {
                        ""type"": ""integer"",
                        ""description"": ""Items per page, 1-500"",
                        ""default"": 100
                    }
                },
                ""additionalProperties"": false
            }",
            Handler = ListCertificatesAsync
        };
    }
}
