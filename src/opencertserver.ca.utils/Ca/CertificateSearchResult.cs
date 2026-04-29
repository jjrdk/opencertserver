namespace OpenCertServer.Ca.Utils.Ca;

using System.Security.Cryptography.X509Certificates;

/// <summary>
/// Paginated search result containing certificate metadata and a total count.
/// </summary>
public class CertificateSearchResult
{
     /// <summary>
     /// Total number of certificates matching the filter (ignoring pagination).
     /// </summary>
    public required long TotalCount { get; set; }

     /// <summary>
     /// The requested page index.
     /// </summary>
    public int Page { get; set; }

     /// <summary>
     /// The requested page size.
     /// </summary>
    public int PageSize { get; set; }

     /// <summary>
     /// Number of items returned in this result.
     /// </summary>
    public int Count => Items.Count;

     /// <summary>
     /// Whether there is a next page.
     /// </summary>
    public bool HasNextPage => (long)(Page + 1) * PageSize < TotalCount;

     /// <summary>
     /// The certificate items on this page.
     /// </summary>
    public required List<CertificateItemInfo> Items { get; set; }
}
