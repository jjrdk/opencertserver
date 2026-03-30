namespace OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// Defines the interface for storing and retrieving CA profiles.
/// </summary>
public interface IStoreCaProfiles : IDisposable
{
    /// <summary>
    /// Gets the CA profile with the specified name. If no profile matches, then returns the default profile.
    /// </summary>
    /// <param name="name">The optional name of the CA profile to retrieve. If null, the default profile is returned.</param>
    /// <param name="cancellationToken">The cancellation token to observe while retrieving the CA profile.</param>
    /// <returns>The CA profile matching the specified name, or the default profile if no match is found.</returns>
    Task<CaProfile> GetProfile(string? name, CancellationToken cancellationToken = default);
}
