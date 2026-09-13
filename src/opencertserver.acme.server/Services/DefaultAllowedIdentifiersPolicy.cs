namespace OpenCertServer.Acme.Server.Services;

using Abstractions.Services;
using CertesSlim.Acme.Resource;

/// <summary>
/// Default <see cref="IAllowedIdentifiersPolicy"/> that rejects .onion identifiers.
/// </summary>
/// <remarks>
/// .onion names are only resolvable through Tor and are not part of the public DNS,
/// so a certificate authority must not issue certificates for them. Every other
/// identifier is permitted.
/// </remarks>
public sealed class DefaultAllowedIdentifiersPolicy : IAllowedIdentifiersPolicy
{
    /// <summary>
    /// The reason reported for rejected .onion identifiers.
    /// </summary>
    public const string OnionRejectionReason =
        "The .onion top-level domain is not part of the public DNS hierarchy.";

    /// <inheritdoc/>
    public string? GetRejectionReason(Identifier identifier)
    {
        ArgumentNullException.ThrowIfNull(identifier);

        var value = Normalize(identifier.Value);
        if (value == "onion" || value.EndsWith(".onion", StringComparison.Ordinal))
        {
            return OnionRejectionReason;
        }

        return null;
    }

    private static string Normalize(string value)
        => value.Trim().TrimEnd('.').ToLowerInvariant();
}