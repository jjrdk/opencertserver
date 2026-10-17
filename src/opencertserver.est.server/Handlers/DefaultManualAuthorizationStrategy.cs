using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Http;

namespace OpenCertServer.Est.Server.Handlers;

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