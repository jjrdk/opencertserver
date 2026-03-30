using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Ca;

/// <summary>
/// Defines the set of CA profiles available for use.
/// </summary>
public class CaProfileSet : IStoreCaProfiles
{
    private readonly string _defaultProfile;
    private readonly IDictionary<string, CaProfile> _profiles;

    /// <summary>
    /// Initializes a new instance of the <see cref="CaProfileSet"/> class.
    /// </summary>
    /// <param name="defaultProfile">The name of the default CA profile.</param>
    /// <param name="profiles">The collection of CA profiles to include in the set.</param>
    /// <exception cref="ArgumentException">Thrown if the default profile is not found in the provided profiles.</exception>
    public CaProfileSet(string defaultProfile, params CaProfile[] profiles)
    {
        _defaultProfile = defaultProfile;
        _profiles = profiles.ToDictionary(p => p.Name, p => p);
        if (!_profiles.ContainsKey(defaultProfile))
        {
            throw new ArgumentException($"Default profile {defaultProfile} not found in profiles");
        }
    }

    /// <inheritdoc />
    public Task<CaProfile> GetProfile(string? name, CancellationToken cancellationToken = default)
    {
        if (name == null)
        {
            return Task.FromResult(_profiles[_defaultProfile]);
        }

        return Task.FromResult(_profiles.TryGetValue(name, out var profile) ? profile : _profiles[_defaultProfile]);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        foreach (var profile in _profiles.Values)
        {
            profile.Dispose();
        }

        GC.SuppressFinalize(this);
    }
}
