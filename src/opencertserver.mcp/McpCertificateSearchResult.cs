namespace OpenCertServer.Mcp;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Paginated result for certificate search.
/// </summary>
public class McpCertificateSearchResult
{
       /// <summary>Total number of certificates matching the filter (ignoring pagination).</summary>
    public required long TotalCount { get; set; }

       /// <summary>Page index (zero-based) of the results returned.</summary>
    public int Page { get; set; }

       /// <summary>Requested page size.</summary>
    public int PageSize { get; set; }

       /// <summary>Number of items on this page.</summary>
    public int Count => Items.Count;

       /// <summary>Whether there are more pages after this one.</summary>
    public bool HasNextPage => (long)(Page + 1) * PageSize < TotalCount;

       /// <summary>Certificate items on this page.</summary>
    public required IReadOnlyList<McpCertificateItem> Items { get; set; }
}
