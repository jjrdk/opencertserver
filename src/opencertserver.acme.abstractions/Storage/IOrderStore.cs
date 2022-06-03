namespace OpenCertServer.Acme.Abstractions.Storage
{
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using Model;

    public interface IOrderStore
    {
        Task<Order?> LoadOrder(string orderId, CancellationToken cancellationToken);

        Task SaveOrder(Order order, CancellationToken cancellationToken);

        Task<List<Order>> GetValidatableOrders(CancellationToken cancellationToken);

        Task<List<Order>> GetFinalizableOrders(CancellationToken cancellationToken);
    }
}
