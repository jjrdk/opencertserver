using System.Security.Cryptography.X509Certificates;

namespace OpenCertServer.Est.Server.Handlers;

using System.Security.Claims;
using Microsoft.AspNetCore.Http;

/// <summary>
/// Determines whether an EST enrollment request should be deferred for manual authorization.
/// </summary>
public interface IManualAuthorizationStrategy
{
    /// <summary>
    /// Evaluates whether the request should be deferred for manual authorization.
    /// </summary>
    bool TryGetPendingAuthorization(
        HttpRequest request,
        ClaimsPrincipal? user,
        CertificateRequest requestContent,
        out TimeSpan retryAfter,
        out string? message);
}

internal sealed class DefaultManualAuthorizationStrategy : IManualAuthorizationStrategy
{
    public bool TryGetPendingAuthorization(
        HttpRequest request,
        ClaimsPrincipal? user,
        CertificateRequest requestContent,
        out TimeSpan retryAfter,
        out string? message)
    {
        retryAfter = TimeSpan.Zero;
        message = null;
        return false;
    }
}
