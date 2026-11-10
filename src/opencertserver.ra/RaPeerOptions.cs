namespace OpenCertServer.Ra;

using Microsoft.Extensions.Configuration;

namespace OpenCertServer.Ra;

/// <summary>Configuration for the outbound-only peer RA client.</summary>
public sealed class RaPeerOptions
{
    /// <summary>Gets the central CA base address. Only HTTPS endpoints are accepted.</summary>
    public required Uri PeerUrl { get; init; }

    /// <summary>Gets the delegated DNS suffix selected for RA operations.</summary>
    public required string Scope { get; init; }

    /// <summary>Gets the CA profile to use, or null to use the CA's default profile.</summary>
    public string? Profile { get; init; }

    /// <summary>
    /// Gets the profiles this RA is delegated to, or empty to be allowed to use every profile the
    /// backing CA supports. A non-empty set restricts the RA to that subset. The set may be refreshed
    /// from the CA via <see cref="RaPeerClient.GetSupportedProfiles"/>.
    /// </summary>
    public IReadOnlyList<string> Profiles { get; init; } = Array.Empty<string>();

    /// <summary>Gets the optional bearer token used to authenticate this RA.</summary>
    public string? BearerToken { get; init; }

    /// <summary>Reads RA peer settings and rejects non-HTTPS or incomplete configuration.</summary>
    public static RaPeerOptions FromConfiguration(IConfiguration configuration)
    {
        var section = configuration.GetSection("Ra");
        var peerUrlText = section["PeerUrl"];
        if (!Uri.TryCreate(peerUrlText, UriKind.Absolute, out var peerUrl) ||
            !string.Equals(peerUrl.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Ra:PeerUrl must be an absolute HTTPS URL.");
        }

        var scope = section["Scope"];
        if (string.IsNullOrWhiteSpace(scope))
        {
            throw new InvalidOperationException("Ra:Scope must contain the delegated DNS suffix.");
        }

        return new RaPeerOptions
        {
            PeerUrl = peerUrl.AbsoluteUri.EndsWith("/", StringComparison.Ordinal)
                ? peerUrl
                : new Uri(peerUrl.AbsoluteUri + "/", UriKind.Absolute),
            Scope = scope,
            Profile = section["Profile"],
            Profiles = ParseProfiles(section["Profiles"]),
            BearerToken = section["BearerToken"]
        };
    }

    /// <summary>
    /// Parses a comma-separated profile list into the delegated profile set; a blank value yields an
    /// empty set, which means "all profiles the CA supports".
    /// </summary>
    private static IReadOnlyList<string> ParseProfiles(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Array.Empty<string>();
        }

        return raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }
}
