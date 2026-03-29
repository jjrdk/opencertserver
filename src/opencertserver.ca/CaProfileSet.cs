using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Ca;

public class CaProfileSet : IStoreCaProfiles
{
    private readonly string _defaultProfile;
    private readonly IDictionary<string, CaProfile> _profiles;

    public CaProfileSet(string defaultProfile, params CaProfile[] profiles)
    {
        _defaultProfile = defaultProfile;
        _profiles = profiles.ToDictionary(p => p.Name, p => p);
        if (!_profiles.ContainsKey(defaultProfile))
        {
            throw new ArgumentException($"Default profile {defaultProfile} not found in profiles");
        }
    }

    public CaProfile GetProfile(string? name)
    {
        if (name == null)
        {
            return _profiles[_defaultProfile];
        }

        if (_profiles.TryGetValue(name, out var profile))
        {
            return profile;
        }

        return _profiles[_defaultProfile];
    }

    public void Dispose()
    {
        foreach (var profile in _profiles.Values)
        {
            profile.Dispose();
        }
        GC.SuppressFinalize(this);
    }
}
