namespace OpenCertServer.Data.Stores;

using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Storage;
using OpenCertServer.Data.Entities;

/// <summary>Relational <see cref="IStoreExternalAccountKeys"/> using the configured EF provider; an EAB key is single-use.</summary>
public sealed class RelationalExternalAccountKeyStore : IStoreExternalAccountKeys
{
    /// <summary>The scope factory used to create a scoped <see cref="CaDbContext"/> per operation.</summary>
    private readonly IServiceScopeFactory _scopeFactory;

    /// <summary>Initializes a new instance of the <see cref="RelationalExternalAccountKeyStore"/> class.</summary>
    /// <param name="scopeFactory">The DI <see cref="IServiceScopeFactory"/>.</param>
    public RelationalExternalAccountKeyStore(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    /// <inheritdoc />
    public async Task<ExternalAccountKey?> LoadKey(string keyId, CancellationToken cancellationToken)
    {
        var entity = await LoadEntity(keyId, cancellationToken);
        return entity is null ? null : FromEntity(entity);
    }

    /// <inheritdoc />
    public async Task SaveKey(ExternalAccountKey key, CancellationToken cancellationToken)
    {
        var entity = new ExternalAccountKeyEntity
        {
            KeyId = key.KeyId,
            MacKey = key.MacKey,
            MacAlgorithm = key.MacAlgorithm,
            IsUsed = key.IsUsed,
            BoundAccountId = key.BoundAccountId,
            BoundAt = key.BoundAt,
            Version = checked(key.Version + 1),
        };

        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        if (key.Version == 0)
        {
            db.ExternalAccountKeys.Add(entity);
        }
        else
        {
            db.ExternalAccountKeys.Update(entity).Property(e => e.Version).OriginalValue = key.Version;
        }

        await db.SaveAggregateAsync(scope.ServiceProvider.GetRequiredService<IRelationalStoreProvider>(), cancellationToken);
        key.Version = entity.Version;
    }

    /// <inheritdoc />
    public async Task<ExternalAccountKey?> FindActiveKey(string keyId, CancellationToken cancellationToken)
    {
        var entity = await LoadEntity(keyId, cancellationToken);
        if (entity is null || entity.IsUsed)
        {
            return null;
        }

        return FromEntity(entity);
    }

    private async Task<ExternalAccountKeyEntity?> LoadEntity(string keyId, CancellationToken cancellationToken)
    {
        var id = keyId;
        var ct = cancellationToken;
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        return await db.ExternalAccountKeys.AsNoTrackingWithIdentityResolution()
            .FirstOrDefaultAsync(e => e.KeyId == id, ct);
    }

    private static ExternalAccountKey FromEntity(ExternalAccountKeyEntity entity)
    {
        return new ExternalAccountKey(entity.KeyId, entity.MacKey, entity.MacAlgorithm,
            entity.IsUsed, entity.BoundAccountId, entity.BoundAt, entity.Version);
    }
}
