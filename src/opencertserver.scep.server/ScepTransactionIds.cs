namespace OpenCertServer.Scep.Server;

using System.Collections.Concurrent;

/// <summary>
/// Remembers accepted requests for a window - by transaction ID and senderNonce - so that a
/// captured PKCSReq or RenewalReq cannot be replayed to have the CA issue again. The nonce is
/// a signed attribute: a replay carries the same one, a new request a new one. The transaction
/// ID alone would not do: clients derive it from the public key (RFC 8894, 3.2.1.1.1), so a
/// renewal with the same key, or a retry after a refusal, carries the ID of the earlier request.
/// <para>
/// The endpoint is anonymous, so only requests that passed the challenge or the renewal check
/// are claimed - a stranger's messages take no room. The store is bounded
/// (<see cref="ScepServerOptions.MaxRememberedRequests"/>) and refuses when full rather than
/// forget a request inside its window; expired entries are swept at most once a minute.
/// In memory, per process: a server running several instances behind a load balancer would
/// need a shared store instead.
/// </para>
/// </summary>
public sealed class ScepTransactionIds(ScepServerOptions options, TimeProvider time)
{
    private static readonly TimeSpan SweepEvery = TimeSpan.FromMinutes(1);

    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);
    private readonly Lock _sweepLock = new();
    private DateTimeOffset _nextSweep = DateTimeOffset.MinValue;

    /// <summary>What a claim came to.</summary>
    public enum ClaimResult
    {
        /// <summary>The request is new and now remembered.</summary>
        Claimed,

        /// <summary>The same request was accepted within the window: a replay.</summary>
        Replayed,

        /// <summary>The store is full; the request is refused rather than risk a replay.</summary>
        Full
    }

    /// <summary>
    /// Whether the same request was already accepted within the window. Takes no room - for
    /// refusing a replay early, before the challenge is checked.
    /// </summary>
    public bool IsKnown(string transactionId, ReadOnlySpan<byte> senderNonce) =>
        _seen.TryGetValue(Key(transactionId, senderNonce), out var claimed)
        && time.GetUtcNow() - claimed < options.TransactionIdWindow;

    /// <summary>
    /// Claims a request that passed its checks, right before the CA issues. Atomic: of two
    /// identical requests racing here, one wins.
    /// </summary>
    public ClaimResult TryClaim(string transactionId, ReadOnlySpan<byte> senderNonce)
    {
        var key = Key(transactionId, senderNonce);
        var now = time.GetUtcNow();
        Sweep(now, force: false);
        if (_seen.Count >= options.MaxRememberedRequests)
        {
            Sweep(now, force: true);
            if (_seen.Count >= options.MaxRememberedRequests)
            {
                return ClaimResult.Full;
            }
        }

        if (_seen.TryAdd(key, now))
        {
            return ClaimResult.Claimed;
        }

        if (!_seen.TryGetValue(key, out var claimed) || now - claimed < options.TransactionIdWindow)
        {
            return ClaimResult.Replayed;
        }

        // Expired but not yet swept: the new claim wins, unless another one did.
        return _seen.TryUpdate(key, now, claimed) ? ClaimResult.Claimed : ClaimResult.Replayed;
    }

    private static string Key(string transactionId, ReadOnlySpan<byte> senderNonce) =>
        transactionId + "/" + Convert.ToHexString(senderNonce);

    private void Sweep(DateTimeOffset now, bool force)
    {
        lock (_sweepLock)
        {
            if (!force && now < _nextSweep)
            {
                return;
            }

            _nextSweep = now + SweepEvery;
        }

        foreach (var (id, claimed) in _seen)
        {
            if (now - claimed >= options.TransactionIdWindow)
            {
                _seen.TryRemove(new KeyValuePair<string, DateTimeOffset>(id, claimed));
            }
        }
    }
}
