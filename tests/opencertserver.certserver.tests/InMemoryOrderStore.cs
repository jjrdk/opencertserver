namespace OpenCertServer.CertServer.Tests;

using Acme.Abstractions.Model;
using Acme.Abstractions.Storage;

internal class InMemoryOrderStore : IOrderStore
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
        var orders = _orders.Values.Where(o => o.Status == OrderStatus.Pending).ToList();
        return Task.FromResult(orders);
    }

    /// <inheritdoc />
    public Task<List<Order>> GetFinalizableOrders(CancellationToken cancellationToken)
    {
        var orders = _orders.Values.Where(o => o.Status == OrderStatus.Valid).ToList();
        return Task.FromResult(orders);
    }
}