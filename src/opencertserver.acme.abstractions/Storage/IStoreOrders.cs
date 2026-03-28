namespace OpenCertServer.Acme.Abstractions.Storage;

using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Model;

/// <summary>
/// Defines a persistence contract for storing, loading, and querying ACME orders.
/// </summary>
public interface IStoreOrders
{
    /// <summary>
    /// Loads an order from the store asynchronously by order ID.
    /// </summary>
    /// <param name="orderId">The order identifier.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The loaded order, or null if not found.</returns>
    Task<Order?> LoadOrder(string orderId, CancellationToken cancellationToken);

    /// <summary>
    /// Saves an order to the store asynchronously.
    /// </summary>
    /// <param name="order">The order to save.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    Task SaveOrder(Order order, CancellationToken cancellationToken);

    /// <summary>
    /// Gets a list of orders that are eligible for validation.
    /// </summary>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>A read-only list of validatable orders.</returns>
    Task<IReadOnlyList<Order>> GetValidatableOrders(CancellationToken cancellationToken);
}
