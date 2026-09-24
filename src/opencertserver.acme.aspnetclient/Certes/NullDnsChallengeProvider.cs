namespace OpenCertServer.Acme.AspNetClient.Certes;

using System;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// The default <see cref="IDnsChallengeProvider"/>. It performs no work, which means a DNS-01 order
/// can be placed but its TXT records are never written, so the ACME server times out and the order
/// fails until a real provider is registered (see <c>AddAcmeDnsChallenge</c>). It exists so the
/// http-01 path is unaffected by the presence of the provider dependency.
/// </summary>
public sealed class NullDnsChallengeProvider : IDnsChallengeProvider
{
    public static readonly NullDnsChallengeProvider Instance = new();

    public Task PlaceChallengesAsync(
        IReadOnlyList<DnsChallengeRecord> records,
        CancellationToken cancellationToken = default)
         => Task.CompletedTask;

    public Task RemoveChallengesAsync(
        IReadOnlyList<DnsChallengeRecord> records,
        CancellationToken cancellationToken = default)
         => Task.CompletedTask;
}
