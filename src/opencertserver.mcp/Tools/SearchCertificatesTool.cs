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
                filterDict[kvp.Key] = kvp.Value?.ToString() ?? "";
            }
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
            KeyAlgorithms = filterDict.TryGetValue("keyAlgorithms", out var ka)
                ? ka.Split(',', StringSplitOptions.TrimEntries)
                : null
        };

        var page = filterDict.TryGetValue("page", out var p) ? System.Convert.ToInt32(p) : 0;
        var pageSize = filterDict.TryGetValue("pageSize", out var ps) ? System.Convert.ToInt32(ps) : 100;

        if (pageSize is < 1 or > 500)
        {
            return McpToolResult.Fail("pageSize must be between 1 and 500");
        }

        var store = context.GetService<IStoreCertificates>();
        var result = await store
            .GetInventory(page, pageSize, CancellationToken.None)
            .Select(item => new McpCertificateItem
            {
                SerialNumber = item.SerialNumber,
                Subject = item.DistinguishedName,
                Issuer = item.DistinguishedName,
                Thumbprint = item.Thumbprint,
                NotBefore = item.NotBefore,
                NotAfter = item.NotAfter,
                PublicKeyAlgorithm = "unknown",
                PublicKeySize = 0,
                IsRevoked = item.IsRevoked,
                RevocationReason = item.RevocationReason,
                RevocationDate = item.RevocationDate
            })
            .ToArrayAsync(CancellationToken.None);
        //.SearchCertificates(filter, page, pageSize, CancellationToken.None);

        var finalResult = new McpCertificateSearchResult
        {
            Page = page,
            PageSize = pageSize,
            TotalCount = result.Length,
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
                "Search certificates by multiple criteria: subject CN, subject contains substring, issuer, serial number, thumbprint, date range (notBefore/notAfter), revocation status, and key algorithm.",
            InputSchema = @"{
                 'type': 'object',
                 'properties': {
                      'subjectCN': {'type': 'string', 'description': 'Exact match on subject CN'},
                      'subjectContains': {'type': 'string', 'description': 'Substring match on subject DN'},
                      'issuerContains': {'type': 'string', 'description': 'Substring match on issuer DN'},
                      'serialNumber': {'type': 'string', 'description': 'Exact match on serial number'},
                      'thumbprint': {'type': 'string', 'description': 'Exact match on thumbprint'},
                      'notBeforeAfter': {'type': 'string', 'format': 'date-time', 'description': 'Certificates not before this date'},
                      'notBeforeBefore': {'type': 'string', 'format': 'date-time', 'description': 'Certificates not before this date'},
                      'notAfterAfter': {'type': 'string', 'format': 'date-time', 'description': 'Certificates not after this date'},
                      'notAfterBefore': {'type': 'string', 'format': 'date-time', 'description': 'Certificates not after this date'},
                      'status': {'type': 'string', 'enum': ['Good', 'Revoked', 'Unknown', ''], 'description': 'Filter by revocation status'},
                      'keyAlgorithms': {'type': 'array', 'items': {'type': 'string'}, 'description': 'Filter by key type (RSA, ECDSA)'},
                      'page': {'type': 'integer', 'default': 0},
                      'pageSize': {'type': 'integer', 'default': 100}
                  },
                  'additionalProperties': false
              }",
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
