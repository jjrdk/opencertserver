namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using OpenCertServer.Est.Server.Handlers;

internal sealed class TestManualAuthorizationStrategy : IManualAuthorizationStrategy
{
    public bool RequireManualAuthorization { get; set; }

    public bool TryGetPendingAuthorization(
        HttpRequest request,
        ClaimsPrincipal? user,
        string requestContent,
        out TimeSpan retryAfter,
        out string? message)
    {
        if (!RequireManualAuthorization)
        {
            retryAfter = TimeSpan.Zero;
            message = null;
            return false;
        }

        RequireManualAuthorization = false;
        retryAfter = TimeSpan.FromMinutes(5);
        message = "Manual authorization pending.";
        return true;
    }
}

