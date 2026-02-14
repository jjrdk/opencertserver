using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Server.Stores;

using Abstractions.Model;
using Abstractions.Storage;

internal sealed class InMemoryOrderStore : IStoreOrders
{
    private readonly Dictionary<string, Order> _orders = new();
    /// <inheritdoc />
    public Task<Order?> LoadOrder(string orderId, CancellationToken cancellationToken)
    {
        _ = _orders.TryGetValue(orderId, out var order);
        return Task.FromResult(order);
    }

    /// <inheritdoc />
    public Task SaveOrder(Order order, CancellationToken cancellationToken)
    {
        _orders[order.OrderId] = order;
        return Task.CompletedTask;
    }

    /// <inheritdoc />
    public Task<List<Order>> GetValidatableOrders(CancellationToken cancellationToken)
    {
        var orders = _orders.Values.Where(
                o => o.Authorizations.Any(a => a.Challenges.Any(c => c.Status == ChallengeStatus.Processing)))
            .ToList();
        return Task.FromResult(orders);
    }
}
