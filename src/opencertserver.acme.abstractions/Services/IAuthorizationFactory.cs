namespace OpenCertServer.Acme.Abstractions.Services;

using Model;

/// <summary>
/// Defines a factory for creating ACME authorizations for an order.
/// </summary>
public interface IAuthorizationFactory
{
    /// <summary>
    /// Creates authorizations for the specified order.
    /// </summary>
    /// <param name="order">The order for which to create authorizations.</param>
    void CreateAuthorizations(Order order);
}
