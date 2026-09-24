namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// List all certificates in the CA store with pagination.
///
/// Input: page (int, default 0), pageSize (int, default 100, max 500)
/// Output: McpCertificateSearchResult with page of certificate metadata
/// </summary>
[McpServerToolType]
public class ListCertificatesTool
{
    [McpServerTool(Name = "list_certificates", ReadOnly = true, Idempotent = true, Destructive = false)]
    [Description("List issued certificates with pagination.")]
    public static async Task<McpCertificateSearchResult> ListCertificatesAsync(
        IStoreCertificates store,
        [Description("Zero-based page index")] int page = 0,
        [Description("Items per page (1-500)")] int pageSize = 100,
        CancellationToken cancellationToken = default)
    {
        if (pageSize is < 1 or > 500)
        {
            throw new McpException("pageSize must be between 1 and 500");
        }

        var inv = store.GetInventory(page, pageSize, cancellationToken);
        var items = await inv.ToListAsync(cancellationToken).ConfigureAwait(false);

        // Estimate total count: if we got fewer items than pageSize, this is the last page.
        // For an accurate total, a dedicated COUNT query would be needed from a persistent store.
        var totalCount = (long)(page + 1) * pageSize;
        if (items.Count < pageSize)
        {
            totalCount = page * pageSize + items.Count;
        }

        return new McpCertificateSearchResult
        {
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount,
            Items = items.Select(info => new McpCertificateItem
            {
                SerialNumber = info.SerialNumber,
                Subject = info.DistinguishedName,
                Issuer = info.Issuer ?? info.DistinguishedName,
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
    }
}
