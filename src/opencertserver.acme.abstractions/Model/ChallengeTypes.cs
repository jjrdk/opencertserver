using System.Collections.Immutable;

namespace OpenCertServer.Acme.Abstractions.Model;

/// <summary>
/// Provides constants and collections for supported ACME challenge types.
/// </summary>
public static class ChallengeTypes
{
    /// <summary>
    /// The HTTP-01 challenge type string.
    /// </summary>
    public const string Http01 = "http-01";
    /// <summary>
    /// The DNS-01 challenge type string.
    /// </summary>
    public const string Dns01 = "dns-01";
    /// <summary>
    /// Gets an immutable array of all supported challenge types.
    /// </summary>
    public static readonly ImmutableArray<string> AllTypes = [Http01, Dns01];
}
