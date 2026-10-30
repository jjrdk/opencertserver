namespace OpenCertServer.Data.Stores;

using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Storage;

/// <summary>Relational <see cref="INonceStore"/> using injected atomic operations, one scope per operation.</summary>
public sealed class RelationalNonceStore : INonceStore
{
    /// <summary>The scope factory used to create a scoped <see cref="CaDbContext"/> per operation.</summary>
    private readonly IServiceScopeFactory _scopeFactory;

    /// <summary>Initializes a new instance of the <see cref="RelationalNonceStore"/> class.</summary>
    /// <param name="scopeFactory">The DI <see cref="IServiceScopeFactory"/>.</param>
    public RelationalNonceStore(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    /// <inheritdoc />
    public async Task SaveNonceAsync(Nonce nonce, CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        await scope.ServiceProvider.GetRequiredService<IRelationalStoreProvider>()
            .SaveNonceAsync(db, nonce, cancellationToken);
    }

    /// <inheritdoc />
    public async Task<bool> TryRemoveNonceAsync(Nonce nonce, CancellationToken cancellationToken)
    {
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        return await scope.ServiceProvider.GetRequiredService<IRelationalStoreProvider>()
            .TryRemoveNonceAsync(db, nonce, cancellationToken);
    }
}
