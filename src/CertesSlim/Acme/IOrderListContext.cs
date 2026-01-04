using CertesSlim.Acme.Resource;

namespace CertesSlim.Acme;

/// <summary>
/// Presents the context for ACME order list operations.
/// </summary>
public interface IOrderListContext : IResourceContext<OrderList>
{
    /// <summary>
    /// Gets the orders.
    /// </summary>
    /// <returns>
    /// The orders.
    /// </returns>
    Task<IEnumerable<IOrderContext>> Orders();
}