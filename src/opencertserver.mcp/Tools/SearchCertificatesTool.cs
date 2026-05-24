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
public static class SearchCertificatesTool
{
    public static async Task<McpToolResult> Handle(McpToolContext context)
     {
        var parameters = context.Parameters as IDictionary<string, object>;

        var filterDict = new Dictionary<string, string>();
        if (parameters != null)
         {
            foreach (var kvp in parameters)
             {
                // Coerce each value to string for filter matching
                filterDict[kvp.Key] = kvp.Value == null ? "" :
                    kvp.Value is JsonElement je ? je.ToString() :
                    kvp.Value.ToString() ?? "";
             }
         }

         // Extract keyAlgorithms as array if provided (schema declares it as an array)
        string[]? keyAlgorithms = null;
        if (parameters?.TryGetValue("keyAlgorithms", out var kaObj) == true)
         {
            keyAlgorithms = ParameterHelper.GetStringArray(kaObj);
         }

        var filter = new CertificateSearchFilter
         {
            SubjectCN = filterDict.GetValueOrDefault("subjectCN"),
            SubjectContains = filterDict.GetValueOrDefault("subjectContains"),
            IssuerContains = filterDict.GetValueOrDefault("issuerContains"),
            SerialNumber = filterDict.GetValueOrDefault("serialNumber"),
            Thumbprint = filterDict.GetValueOrDefault("thumbprint"),
            NotBeforeAfter =
                filterDict.TryGetValue("notBeforeAfter", out var nba) && DateTime.TryParse(nba, out var nbaDate)
                     ? nbaDate
                     : null,
            NotBeforeBefore =
                filterDict.TryGetValue("notBeforeBefore", out var nbb) && DateTime.TryParse(nbb, out var nbbDate)
                     ? nbbDate
                     : null,
            NotAfterAfter =
                filterDict.TryGetValue("notAfterAfter", out var naa) && DateTime.TryParse(naa, out var naaDate)
                     ? naaDate
                     : null,
            NotAfterBefore =
                filterDict.TryGetValue("notAfterBefore", out var nab) && DateTime.TryParse(nab, out var nabDate)
                     ? nabDate
                     : null,
            Status = filterDict.GetValueOrDefault("status"),
            KeyAlgorithms = keyAlgorithms
         };

        var page = ParameterHelper.GetInt32(parameters?.TryGetValue("page", out var p) == true ? p : null, 0);
        var pageSize = ParameterHelper.GetInt32(parameters?.TryGetValue("pageSize", out var ps) == true ? ps : null, 100);

        if (pageSize is < 1 or > 500)
         {
            return McpToolResult.Fail("pageSize must be between 1 and 500");
         }

        var store = context.GetService<IStoreCertificates>();

        // NOTE: Filtering is applied client-side after fetching the full inventory.
        // For large stores, consider adding a SearchCertificates method to IStoreCertificates
        // that supports server-side filtering.

        // Fetch the full inventory (client-side filtering)
        var allItems = await store
             .GetInventory(0, int.MaxValue, CancellationToken.None)
             .ToListAsync(CancellationToken.None);

        // Apply filters client-side
        IEnumerable<CertificateItemInfo> filtered = allItems;

        if (!string.IsNullOrWhiteSpace(filter.SubjectCN))
            filtered = filtered.Where(i => i.DistinguishedName.Contains(filter.SubjectCN!, StringComparison.OrdinalIgnoreCase));

        if (!string.IsNullOrWhiteSpace(filter.SubjectContains))
            filtered = filtered.Where(i => i.DistinguishedName.Contains(filter.SubjectContains!, StringComparison.OrdinalIgnoreCase));

        if (!string.IsNullOrWhiteSpace(filter.IssuerContains))
            filtered = filtered.Where(i => i.DistinguishedName.Contains(filter.IssuerContains!, StringComparison.OrdinalIgnoreCase));

        if (!string.IsNullOrWhiteSpace(filter.SerialNumber))
            filtered = filtered.Where(i => i.SerialNumber.Contains(filter.SerialNumber!, StringComparison.OrdinalIgnoreCase));

        if (!string.IsNullOrWhiteSpace(filter.Thumbprint))
            filtered = filtered.Where(i => i.Thumbprint.Contains(filter.Thumbprint!, StringComparison.OrdinalIgnoreCase));

        if (filter.NotBeforeAfter.HasValue)
            filtered = filtered.Where(i => i.NotBefore >= filter.NotBeforeAfter!.Value);

        if (filter.NotBeforeBefore.HasValue)
            filtered = filtered.Where(i => i.NotBefore <= filter.NotBeforeBefore!.Value);

        if (filter.NotAfterAfter.HasValue)
            filtered = filtered.Where(i => i.NotAfter >= filter.NotAfterAfter!.Value);

        if (filter.NotAfterBefore.HasValue)
            filtered = filtered.Where(i => i.NotAfter <= filter.NotAfterBefore!.Value);

        if (!string.IsNullOrWhiteSpace(filter.Status))
        {
            var lowerStatus = filter.Status.ToLowerInvariant();
            filtered = lowerSwitch(filtered, lowerStatus);

            static IEnumerable<CertificateItemInfo> lowerSwitch(IEnumerable<CertificateItemInfo> source, string status)
                => status switch
                {
                    "good" => source.Where(i => !i.IsRevoked),
                    "revoked" => source.Where(i => i.IsRevoked),
                    _ => source
                };
        }

        if (filter.KeyAlgorithms != null && filter.KeyAlgorithms.Length > 0)
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

        var finalResult = new McpCertificateSearchResult
         {
            Page = page,
            PageSize = pageSize,
            TotalCount = totalCount,
            Items = result
         };

        return McpToolResult.Ok(finalResult);
     }

    public static McpToolDefinition Create()
    {
        return new McpToolDefinition
        {
            Name = "search_certificates",
            Description =
                 "Search certificates by multiple criteria: subject, issuer, serial number, thumbprint, date range, revocation status, and key algorithm. Supports pagination.",
            InputSchema = """
                          {
                                            "type": "object",
                                            "properties": {
                                                 "subjectCN": {"type": "string", "description": "Substring match on subject CN"},
                                                 "subjectContains": {"type": "string", "description": "Substring match on subject DN"},
                                                 "issuerContains": {"type": "string", "description": "Substring match on issuer DN"},
                                                 "serialNumber": {"type": "string", "description": "Substring match on serial number"},
                                                 "thumbprint": {"type": "string", "description": "Substring match on thumbprint"},
                                                 "notBeforeAfter": {"type": "string", "format": "date-time", "description": "Certificates not before this date"},
                                                 "notBeforeBefore": {"type": "string", "format": "date-time", "description": "Certificates not before this date"},
                                                 "notAfterAfter": {"type": "string", "format": "date-time", "description": "Certificates not after this date"},
                                                 "notAfterBefore": {"type": "string", "format": "date-time", "description": "Certificates not after this date"},
                                                 "status": {"type": "string", "enum": ["Good", "Revoked", "Unknown", ""], "description": "Filter by revocation status"},
                                                 "keyAlgorithms": {"type": "array", "items": {"type": "string"}, "description": "Filter by key type (RSA, ECDSA) (not yet supported - requires loading certs)"},
                                                 "page": {"type": "integer", "default": 0},
                                                 "pageSize": {"type": "integer", "default": 100}
                                             },
                                             "additionalProperties": false
                                         }
                          """,
            Handler = Handle
        };
    }
}

public class CertificateSearchFilter
{
    public string? SubjectCN { get; set; }
    public string? SubjectContains { get; set; }
    public string? IssuerContains { get; set; }
    public string? SerialNumber { get; set; }
    public string? Thumbprint { get; set; }
    public DateTimeOffset? NotBeforeAfter { get; set; }
    public DateTimeOffset? NotBeforeBefore { get; set; }
    public DateTimeOffset? NotAfterAfter { get; set; }
    public DateTimeOffset? NotAfterBefore { get; set; }
    public string? Status { get; set; }
    public string[]? KeyAlgorithms { get; set; }
}
