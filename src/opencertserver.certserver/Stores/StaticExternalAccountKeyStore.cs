// This file is licensed under the terms in the README file of OpenCertServer.
// This file is part of OpenCertServer.

// A read-mostly external account key (RFC 8555 §7.3.4) store seeded from configuration at startup.
//
// The ACME server ships an empty in-memory EAB key store, which cannot bind any external account.
// Installing this store, configured out-of-band, lets a hardened deployment accept EAB-authenticated
// account creation without ever writing a credential to disk.
namespace OpenCertServer.CertServer.Stores;

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Acme.Abstractions.Model;
using Acme.Abstractions.Storage;

/// <summary>
/// An <see cref="IStoreExternalAccountKeys"/> backed by an immutable, configuration-seeded set of
/// external account keys, so no credential is written to disk.
/// </summary>
public sealed class StaticExternalAccountKeyStore : IStoreExternalAccountKeys
{
    private readonly IReadOnlyDictionary<string, ExternalAccountKey> _keys;
    private readonly object _sync = new();

    /// <summary>Initializes a new instance of the <see cref="StaticExternalAccountKeyStore"/> class.</summary>
    /// <param name="keys">The external account keys, provisioned out-of-band.</param>
    public StaticExternalAccountKeyStore(IEnumerable<ExternalAccountKey> keys)
    {
        _keys =
            keys.ToDictionary(k => k.KeyId, StringComparer.Ordinal);
    }

    /// <inheritdoc />
    public Task<ExternalAccountKey?> LoadKey(string keyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            _ = _keys.TryGetValue(keyId, out var key);
            return Task.FromResult(key);
        }
    }

    /// <inheritdoc />
    public Task SaveKey(ExternalAccountKey key, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        // Keys are provisioned out-of-band; a static store is not a place to bind new ones.
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<ExternalAccountKey?> FindActiveKey(string keyId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            _ = _keys.TryGetValue(keyId, out var key);
            return Task.FromResult(key is { IsUsed: not true } ? key : null);
        }
    }

    /// <inheritdoc />
    public Task<bool> TryConsumeKey(string keyId, string? accountId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            if (!_keys.TryGetValue(keyId, out var key) || key.IsUsed)
            {
                return Task.FromResult(false);
            }

            key.MarkUsed(accountId);
            return Task.FromResult(true);
        }
    }
}
