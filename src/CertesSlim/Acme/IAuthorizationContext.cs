namespace CertesSlim.Acme;

using CertesSlim.Acme.Resource;

/// <summary>
/// Supports ACME authorization operations.
/// </summary>
public interface IAuthorizationContext : IResourceContext<Authorization>
{
    /// <summary>
    /// Gets the challenges for this authorization.
    /// </summary>
    /// <returns>The list fo challenges.</returns>
    Task<IEnumerable<IChallengeContext>> Challenges();

    /// <summary>
    /// Deactivates this authorization.
    /// </summary>
    /// <returns>
    /// The authorization deactivated.
    /// </returns>
    Task<Authorization> Deactivate();
}
