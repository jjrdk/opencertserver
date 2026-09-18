namespace OpenCertServer.Acme.Server.Services;

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using DnsClientX;

/// <summary>
/// Resolves DNS resource records used during ACME challenge and CAA validation.
/// </summary>
/// <remarks>
/// Implementations must throw <see cref="DnsClientException"/> when the DNS
/// lookup fails, while an empty result represents a successful lookup with no
/// matching records.
/// </remarks>
public interface IDnsResolver
{
    /// <summary>
    /// Resolves the CAA record set for the given name.
    /// </summary>
    /// <param name="name">The name to query.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The matching CAA records, or an empty list when none are present.</returns>
    Task<IReadOnlyList<CaaRecord>> ResolveCaaRecordsAsync(
        string name,
        CancellationToken cancellationToken);

    /// <summary>
    /// Resolves the TXT record set for the given name.
    /// </summary>
    /// <param name="name">The name to query.</param>
    /// <param name="cancellationToken">Token used to cancel the operation.</param>
    /// <returns>The text content of the matching TXT records, or an empty list when none are present.</returns>
    Task<IReadOnlyList<string>> ResolveTxtRecordsAsync(
        string name,
        CancellationToken cancellationToken);
}