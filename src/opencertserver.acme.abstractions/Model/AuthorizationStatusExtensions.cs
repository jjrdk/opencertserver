using CertesSlim.Acme.Resource;

namespace OpenCertServer.Acme.Abstractions.Model;

using System.Linq;

/// <summary>
/// Provides extension methods for the <see cref="AuthorizationStatus"/> enum.
/// </summary>
public static class AuthorizationStatusExtensions
{
    private static readonly AuthorizationStatus[] InvalidStatus =
    [
        AuthorizationStatus.Invalid,
        AuthorizationStatus.Deactivated,
        AuthorizationStatus.Expired,
        AuthorizationStatus.Revoked
    ];

    /// <summary>
    /// Determines whether the status is considered invalid (deactivated, expired, revoked, or invalid).
    /// </summary>
    /// <param name="status">The authorization status to check.</param>
    /// <returns>True if the status is invalid; otherwise, false.</returns>
    public static bool IsInvalid(this AuthorizationStatus status)
    {
        return InvalidStatus.Contains(status);
    }
}
