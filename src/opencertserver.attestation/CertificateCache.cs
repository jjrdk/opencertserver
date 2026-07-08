using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Attestation;

/// <summary>
/// Per-provider cache for device certificates to prevent hitting vendor gateways (PCCS/VPS)
/// on every attestation request, per spec section 8.4.
/// </summary>
public interface ICertificateCache
{
    X509Certificate2? Get(string deviceId);
    void Set(string deviceId, X509Certificate2 certificate, TimeSpan ttl);
}

/// <summary>
/// Thread-safe in-memory certificate cache backed by a <see cref="ConcurrentDictionary"/>.
/// </summary>
public sealed class InMemoryCertificateCache : ICertificateCache
{
    private readonly record struct CacheEntry(X509Certificate2 Certificate, DateTime ExpiresAt);
    private readonly ConcurrentDictionary<string, CacheEntry> _store = new(StringComparer.OrdinalIgnoreCase);

    public X509Certificate2? Get(string deviceId)
    {
        if (_store.TryGetValue(deviceId, out var entry))
        {
            if (DateTime.UtcNow < entry.ExpiresAt)
                return entry.Certificate;

            _store.TryRemove(deviceId, out _);
        }
        return null;
    }

    public void Set(string deviceId, X509Certificate2 certificate, TimeSpan ttl)
    {
        var entry = new CacheEntry(certificate, DateTime.UtcNow.Add(ttl));
        _store[deviceId] = entry;
    }
}
