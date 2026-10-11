namespace OpenCertServer.Scep.Server;

using System.Collections.Concurrent;

/// <summary>
/// Remembers the transaction IDs of accepted requests for a window, so that a captured
/// PKCSReq or RenewalReq cannot be replayed to have the CA issue again. In memory, per
/// process: a server running several instances behind a load balancer would need a shared
/// store instead.
/// </summary>
public sealed class ScepTransactionIds(ScepServerOptions options, TimeProvider time)
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);

    /// <summary>
    /// Claims a transaction ID. False when it was already claimed within the window.
    /// </summary>
    public bool TryClaim(string transactionId)
    {
        var now = time.GetUtcNow();
        Prune(now);
        if (_seen.TryAdd(transactionId, now))
        {
            return true;
        }

        if (!_seen.TryGetValue(transactionId, out var claimed) || now - claimed < options.TransactionIdWindow)
        {
            return false;
        }

        // Expired between the prune and here: the new claim wins, unless another one did.
        return _seen.TryUpdate(transactionId, now, claimed);
    }

    private void Prune(DateTimeOffset now)
    {
        foreach (var (id, claimed) in _seen)
        {
            if (now - claimed >= options.TransactionIdWindow)
            {
                _seen.TryRemove(new KeyValuePair<string, DateTimeOffset>(id, claimed));
            }
        }
    }
}
