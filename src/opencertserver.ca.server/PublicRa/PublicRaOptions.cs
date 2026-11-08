using System;
using System.Collections.Generic;
using System.Linq;

namespace OpenCertServer.Ca.Server.PublicRa;

using Microsoft.Extensions.Configuration;

/// <summary>
/// Settings for the opt-in public self-service enrollment surface.
/// </summary>
public sealed class PublicRaOptions
{
    /// <summary>Gets whether anonymous enrollment and its abuse controls are enabled.</summary>
    public bool Enabled { get; init; }

    /// <summary>Gets the maximum public enrollment requests per client IP per minute.</summary>
    public int RateLimit { get; init; } = 60;

    /// <summary>Gets whether ACME accounts must be created with external account binding.</summary>
    public bool RequireEab { get; init; }

    /// <summary>Gets whether issuance must wait for human approval.</summary>
    public bool RequireApproval { get; init; }

    /// <summary>Gets the profile names explicitly exposed through the public RA.</summary>
    public IReadOnlyCollection<string> Profiles { get; init; } = [];

    /// <summary>Reads public-RA settings without reflecting over configuration values.</summary>
    public static PublicRaOptions FromConfiguration(IConfiguration configuration)
    {
        var section = configuration.GetSection("PublicRa");
        var profiles = section.GetSection("Profiles").GetChildren()
            .Select(child => child.Value)
            .OfType<string>()
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();
        if (profiles.Length == 0 && section["Profiles"] is { } singleProfile)
        {
            profiles = singleProfile.Split([',', ';', ' ', '\t', '\n'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        return new PublicRaOptions
        {
            Enabled = bool.TryParse(section["Enabled"], out var enabled) && enabled,
            RateLimit = int.TryParse(section["RateLimit"], out var rateLimit) ? rateLimit : 60,
            RequireEab = bool.TryParse(section["RequireEab"], out var requireEab) && requireEab,
            RequireApproval = bool.TryParse(section["RequireApproval"], out var requireApproval) && requireApproval,
            Profiles = profiles
        };
    }
}
