namespace OpenCertServer.Acme.Abstractions.Storage;

using System.Threading;
using System.Threading.Tasks;
using Model;

/// <summary>
/// Defines a persistence contract for storing and loading ACME accounts.
/// </summary>
public interface IStoreAccounts
{
    /// <summary>
    /// Saves an account to the store asynchronously.
    /// </summary>
    /// <param name="account">The account to save.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    Task SaveAccount(Account account, CancellationToken cancellationToken);

    /// <summary>
    /// Loads an account from the store asynchronously by account ID.
    /// </summary>
    /// <param name="accountId">The account identifier.</param>
    /// <param name="cancellationToken">A cancellation token.</param>
    /// <returns>The loaded account, or null if not found.</returns>
    Task<Account?> LoadAccount(string accountId, CancellationToken cancellationToken);
}
