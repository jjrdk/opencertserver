namespace OpenCertServer.Acme.Abstractions.Storage
{
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using Model;

    public interface IStoreOrders
    {
        Task<Order?> LoadOrder(string orderId, CancellationToken cancellationToken);

        Task SaveOrder(Order order, CancellationToken cancellationToken);

        Task<List<Order>> GetValidatableOrders(CancellationToken cancellationToken);
    }
}
