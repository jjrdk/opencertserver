namespace OpenCertServer.Scep.Server;

using System.Collections.Concurrent;

/// <summary>
/// Remembers accepted requests for a window - by transaction ID and senderNonce - so that a
/// captured PKCSReq or RenewalReq cannot be replayed to have the CA issue again. The nonce is
/// a signed attribute: a replay carries the same one, a new request a new one. The transaction
/// ID alone would not do: clients derive it from the public key (RFC 8894, 3.2.1.1.1), so a
/// renewal with the same key, or a retry after a refusal, carries the ID of the earlier request.
/// In memory, per process: a server running several instances behind a load balancer would
/// need a shared store instead.
/// </summary>
public sealed class ScepTransactionIds(ScepServerOptions options, TimeProvider time)
{
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seen = new(StringComparer.Ordinal);

    /// <summary>
    /// Claims a request. False when the same transaction ID and senderNonce were already
    /// claimed within the window.
    /// </summary>
    public bool TryClaim(string transactionId, ReadOnlySpan<byte> senderNonce)
    {
        var key = transactionId + "/" + Convert.ToHexString(senderNonce);
        var now = time.GetUtcNow();
        Prune(now);
        if (_seen.TryAdd(key, now))
        {
            return true;
        }

        if (!_seen.TryGetValue(key, out var claimed) || now - claimed < options.TransactionIdWindow)
        {
            return false;
        }

        // Expired between the prune and here: the new claim wins, unless another one did.
        return _seen.TryUpdate(key, now, claimed);
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
