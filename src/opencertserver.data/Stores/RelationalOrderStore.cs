using System.Text.Json;

namespace OpenCertServer.Data.Stores;

using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Storage;
using OpenCertServer.Data.Entities;
using OpenCertServer.Data.Serialization;

/// <summary>Relational <see cref="IStoreOrders"/> using the configured EF provider, one scope per operation.</summary>
public sealed class RelationalOrderStore : IStoreOrders
{
    /// <summary>The scope factory used to create a scoped <see cref="CaDbContext"/> per operation.</summary>
    private readonly IServiceScopeFactory _scopeFactory;

    /// <summary>Initializes a new instance of the <see cref="RelationalOrderStore"/> class.</summary>
    /// <param name="scopeFactory">The DI <see cref="IServiceScopeFactory"/>.</param>
    public RelationalOrderStore(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    /// <inheritdoc />
    public async Task<Order?> LoadOrder(string orderId, CancellationToken cancellationToken)
    {
        var id = orderId;
        var ct = cancellationToken;
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var entity = await db.Orders.AsNoTrackingWithIdentityResolution().FirstOrDefaultAsync(e => e.OrderId == id, ct);
        return entity is null ? null : FromEntity(entity);
    }

    /// <inheritdoc />
    public async Task SaveOrder(Order order, CancellationToken cancellationToken)
    {
        var entity = new OrderEntity
        {
            OrderId = order.OrderId,
            AccountId = order.AccountId,
            Status = order.Status.ToString(),
            HasProcessingChallenge = order.Authorizations.Any(a =>
                a.Challenges.Any(c => c.Status == CertesSlim.Acme.Resource.ChallengeStatus.Processing)),
            Payload = JsonSerializer.Serialize(order, DataSerializerContext.Default.Order),
            Version = checked(order.Version + 1),
        };

        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        if (order.Version == 0)
        {
            db.Orders.Add(entity);
        }
        else
        {
            db.Orders.Update(entity).Property(e => e.Version).OriginalValue = order.Version;
        }

        await db.SaveAggregateAsync(scope.ServiceProvider.GetRequiredService<IRelationalStoreProvider>(),
            cancellationToken);
        order.Version = entity.Version;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<Order>> GetValidatableOrders(CancellationToken cancellationToken)
    {
        var ct = cancellationToken;
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var rows = await db.Orders.AsNoTrackingWithIdentityResolution()
            .Where(o => o.HasProcessingChallenge)
            .OrderBy(o => o.OrderId)
            .ToListAsync(ct);
        var result = new List<Order>(rows.Count);
        foreach (var row in rows)
        {
            result.Add(FromEntity(row));
        }

        return result;
    }

    /// <inheritdoc />
    public async Task<IReadOnlyList<string>> GetOrderIds(string accountId, CancellationToken cancellationToken)
    {
        var id = accountId;
        var ct = cancellationToken;
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        return await db.Orders.AsNoTracking()
            .Where(o => o.AccountId == id)
            .OrderBy(o => o.OrderId)
            .Select(o => o.OrderId)
            .ToListAsync(ct);
    }

    private static Order FromEntity(OrderEntity entity)
    {
        var order = JsonSerializer.Deserialize(entity.Payload, DataSerializerContext.Default.Order)!;
        order.Version = entity.Version;
        return order;
    }
}
