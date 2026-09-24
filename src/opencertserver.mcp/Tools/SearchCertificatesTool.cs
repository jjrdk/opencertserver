namespace OpenCertServer.Mcp.Tools;

/// <summary>
/// Search certificates by multiple criteria: subject CN contains, issuer contains,
/// date range, revocation status, key algorithm.
///
/// Input: filter object with optional fields (subjectCN, subjectContains,
///        issuerContains, serialNumber, thumbprint, notBeforeAfter, notBeforeBefore,
///        notAfterAfter, notAfterBefore, status, keyAlgorithms) + pagination
/// Output: McpCertificateSearchResult with filtered results
/// </summary>
[McpServerToolType]
public class SearchCertificatesTool
{
    [McpServerTool(Name = "search_certificates", ReadOnly = true, Idempotent = true, Destructive = false)]
    [Description("Search certificates by subject, issuer, serial, thumbprint, validity dates, and status.")]
    public static async Task<McpCertificateSearchResult> SearchCertificates(
        IStoreCertificates store,
        [Description("Substring match on subject CN")] string? subjectCN = null,
        [Description("Substring match on subject DN")] string? subjectContains = null,
        [Description("Substring match on issuer DN")] string? issuerContains = null,
        [Description("Substring match on serial number")] string? serialNumber = null,
        [Description("Substring match on thumbprint")] string? thumbprint = null,
        [Description("Certificates not before this date")] DateTimeOffset? notBeforeAfter = null,
        [Description("Certificates not before this date")] DateTimeOffset? notBeforeBefore = null,
        [Description("Certificates not after this date")] DateTimeOffset? notAfterAfter = null,
        [Description("Certificates not after this date")] DateTimeOffset? notAfterBefore = null,
        [Description("Filter by revocation status: Good or Revoked")] string? status = null,
        [Description("Filter by key type (RSA, ECDSA) - currently not supported")] string[]? keyAlgorithms = null,
        [Description("Zero-based page index")] int page = 0,
        [Description("Items per page (1-500)")] int pageSize = 100,
        CancellationToken cancellationToken = default)
    {
        if (pageSize is < 1 or > 500)
        {
            throw new McpException("pageSize must be between 1 and 500");
        }

        // NOTE: Filtering is applied client-side after fetching the full inventory.
        // For large stores, consider adding a SearchCertificates method to IStoreCertificates
        // that supports server-side filtering.

        // Fetch the full inventory (client-side filtering)
        var allItems = await store
            .GetInventory(0, int.MaxValue, cancellationToken)
            .ToListAsync(cancellationToken).ConfigureAwait(false);

        // Apply filters client-side
        IEnumerable<CertificateItemInfo> filtered = allItems;

        if (!string.IsNullOrWhiteSpace(subjectCN))
        {
            filtered = filtered.Where(i => i.DistinguishedName.Contains(subjectCN, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(subjectContains))
        {
            filtered = filtered.Where(i => i.DistinguishedName.Contains(subjectContains, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(issuerContains))
        {
            filtered = filtered.Where(i => i.DistinguishedName.Contains(issuerContains, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(serialNumber))
        {
            filtered = filtered.Where(i => i.SerialNumber.Contains(serialNumber, StringComparison.OrdinalIgnoreCase));
        }

        if (!string.IsNullOrWhiteSpace(thumbprint))
        {
            filtered = filtered.Where(i => i.Thumbprint.Contains(thumbprint, StringComparison.OrdinalIgnoreCase));
        }

        if (notBeforeAfter.HasValue)
        {
            filtered = filtered.Where(i => i.NotBefore >= notBeforeAfter.Value);
        }

        if (notBeforeBefore.HasValue)
        {
            filtered = filtered.Where(i => i.NotBefore <= notBeforeBefore.Value);
        }

        if (notAfterAfter.HasValue)
        {
            filtered = filtered.Where(i => i.NotAfter >= notAfterAfter.Value);
        }

        if (notAfterBefore.HasValue)
        {
            filtered = filtered.Where(i => i.NotAfter <= notAfterBefore.Value);
        }

        if (!string.IsNullOrWhiteSpace(status))
        {
            var lowerStatus = status.ToLowerInvariant();
            filtered = lowerSwitch(filtered, lowerStatus);

            static IEnumerable<CertificateItemInfo> lowerSwitch(IEnumerable<CertificateItemInfo> source, string status)
                => status switch
                {
                    "good" => source.Where(i => !i.IsRevoked),
                    "revoked" => source.Where(i => i.IsRevoked),
                    _ => source
                };
        }

        if (keyAlgorithms != null && keyAlgorithms.Length > 0)
        {
            // CertificateItemInfo doesn't carry public key OID, so actual key algorithm
            // filtering isn't possible without loading each certificate.
            // TODO: Extend CertificateItemInfo or load certs to support key algorithm filtering.
        }

        // Paginate the filtered results
        var totalCount = filtered.Count();
        var pageItems = filtered.Skip(page * pageSize).Take(pageSize).ToList();

        var result = pageItems.Select(item => new McpCertificateItem
        {
            SerialNumber = item.SerialNumber,
            Subject = item.DistinguishedName,
            Issuer = item.Issuer ?? item.DistinguishedName,
            Thumbprint = item.Thumbprint,
            NotBefore = item.NotBefore,
            NotAfter = item.NotAfter,
            PublicKeyAlgorithm = "unknown",
            PublicKeySize = 0,
            IsRevoked = item.IsRevoked,
            RevocationReason = item.RevocationReason,
            RevocationDate = item.RevocationDate
        }).ToArray();

        return new McpCertificateSearchResult
        {
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount,
            Items = result
        };
    }
}
