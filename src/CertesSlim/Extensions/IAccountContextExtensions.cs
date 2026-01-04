using CertesSlim.Acme;
using CertesSlim.Acme.Resource;

namespace CertesSlim.Extensions;

/// <summary>
/// Extension methods for <see cref="IAccountContext"/>.
/// </summary>
public static class IAccountContextExtensions
{
    /// <param name="account">The account.</param>
    extension(Task<IAccountContext> account)
    {
        /// <summary>
        /// Deactivates the current account.
        /// </summary>
        /// <returns>The account deactivated.</returns>
        public Task<Account> Deactivate()
            => account.ContinueWith(a => a.Result.Deactivate()).Unwrap();

        /// <summary>
        /// Gets the location of the account.
        /// </summary>
        /// <returns>The location URI.</returns>
        public Task<Uri> Location()
            => account.ContinueWith(r => r.Result.Location);
    }
}