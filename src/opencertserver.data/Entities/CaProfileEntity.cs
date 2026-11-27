namespace OpenCertServer.Data.Entities;

/// <summary>
/// EF Core entity backing a persisted <see cref="OpenCertServer.Ca.Utils.Ca.CaProfile"/>.
/// The full profile is stored as a JSON <see cref="Payload"/> (keys and certificates as PEM); the
/// <see cref="Name"/> is the key and <see cref="IsDefault"/> marks the profile returned when no name,
/// or an unknown name, is requested.
/// </summary>
public class CaProfileEntity
{
    /// <summary>The profile name, and the primary key.</summary>
    public required string Name { get; set; }

    /// <summary>Whether this is the default profile, returned for a null or unknown name.</summary>
    public bool IsDefault { get; set; }

    /// <summary>JSON-serialized <see cref="OpenCertServer.Ca.Utils.Ca.CaProfile"/> payload.</summary>
    public required string Payload { get; set; }
}
