using System;
using System.Collections.Generic;
using System.Linq;
using OpenCertServer.Ca.Protocol;

namespace OpenCertServer.Ca.Server.RegistrationAuthority;

using Microsoft.Extensions.Configuration;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>
/// CA-side settings for accepting scoped registration-authority requests.
/// </summary>
public sealed class RaServerOptions
{
    /// <summary>Gets whether RA identities are accepted.</summary>
    public bool AcceptRa { get; init; }

    /// <summary>Gets the configured RA bindings.</summary>
    public IReadOnlyCollection<RaBinding> Bindings { get; init; } = [];

    /// <summary>
    /// Reads the non-secret CA-side RA configuration. Bindings are configuration-backed by
    /// default; hosts may register another <see cref="IStoreRas"/> before calling AddRa.
    /// </summary>
    public static RaServerOptions FromConfiguration(IConfiguration configuration)
    {
        var section = configuration.GetSection("Ca");
        var bindings = section.GetSection("RaBindings").GetChildren().Select(binding =>
        {
            var id = binding["RaId"] ?? binding["Id"];
            if (string.IsNullOrWhiteSpace(id))
            {
                throw new InvalidOperationException("Each Ca:RaBindings entry must define RaId.");
            }

            var scopes = ReadValues(binding.GetSection("Scopes"));
            var profiles = ReadValues(binding.GetSection("Profiles"));
            if (scopes.Count == 0 || profiles.Count == 0)
            {
                throw new InvalidOperationException(
                    $"RA binding '{id}' must define at least one DNS scope and one CA profile.");
            }

            return new RaBinding(
                id,
                new HashSet<string>(scopes, StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(profiles, StringComparer.OrdinalIgnoreCase));
        }).ToArray();

        return new RaServerOptions
        {
            AcceptRa = bool.TryParse(section["AcceptRa"], out var acceptRa) && acceptRa,
            Bindings = bindings
        };
    }

    private static List<string> ReadValues(IConfigurationSection section)
    {
        var values = section.GetChildren().Select(child => child.Value)
            .OfType<string>()
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToList();
        if (values.Count == 0 && section.Value is { } singleValue)
        {
            values.AddRange(singleValue.Split([',', ';', ' ', '\t', '\n'],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
        }

        return values;
    }
}
