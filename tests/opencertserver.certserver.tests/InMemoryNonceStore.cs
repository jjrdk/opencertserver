﻿namespace OpenCertServer.CertServer.Tests;

using Acme.Abstractions.Model;
using Acme.Abstractions.Storage;

internal class InMemoryNonceStore : INonceStore
{
    private readonly HashSet<Nonce> _nonces = new();

    /// <inheritdoc />
    public Task SaveNonceAsync(Nonce nonce, CancellationToken cancellationToken)
    {
        _nonces.Add(nonce);
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<bool> TryRemoveNonceAsync(Nonce nonce, CancellationToken cancellationToken)
    {
        var result = _nonces.Remove(nonce);
        return Task.FromResult(result);
    }
}