namespace OpenCertServer.Acme.AspNetClient.Certes;

using System;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// The <c>_acme-challenge</c> TXT record a provider was asked to publish: the <see cref="Name"/> is
/// the fully-qualified record name (<c>_acme-challenge.&lt;identifier&gt;</c>) and the
/// <see cref="Value"/> is the base64url-encoded SHA-256 digest of the key authorization that the ACME
/// server expects at that name.
/// </summary>
public sealed record DnsChallengeRecord(string Name, string Value);

/// <summary>
/// Publishes and removes the <c>dns-01</c> ACME challenge TXT records required to complete a
/// DNS-01 order. The HTTP-01 challenge is answered by the in-process
/// <c>AcmeChallengeApprovalMiddleware</c>, but a DNS-01 challenge can only be satisfied by writing a
/// TXT record into the DNS zone, which is infrastructure outside the application. This abstraction
/// lets a host plug in its own provider (Cloudflare, Route53, Azure DNS, a static zone, ...).
/// </summary>
/// <remarks>
/// When no provider is registered the <see cref="NullDnsChallengeProvider"/> is used, which makes
/// DNS-01 a no-op. That is the safe default: the http-01 path is unaffected because the provider is
/// only invoked when the order's challenge type is <see cref="ChallengeType.Dns01"/>.
/// </remarks>
public interface IDnsChallengeProvider
{
    /// <summary>
    /// Publishes the TXT records for a placed order so the ACME server can validate them.
    /// </summary>
    /// <param name="records">The records to publish, one per order identifier.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    Task PlaceChallengesAsync(
        IReadOnlyList<DnsChallengeRecord> records,
        CancellationToken cancellationToken = default);

    /// <summary>
    /// Removes the TXT records created for a completed order so the zone does not retain stale
    /// key-authentication material.
    /// </summary>
    /// <param name="records">The records to remove. A provider that cannot delete an individual
    /// record must remove every record it can; the call is idempotent.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    Task RemoveChallengesAsync(
        IReadOnlyList<DnsChallengeRecord> records,
        CancellationToken cancellationToken = default);
}
