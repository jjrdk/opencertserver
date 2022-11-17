namespace OpenCertServer.Acme.AspNetClient.Certes;

using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Persistence;

public sealed class AcmeChallengeApprovalMiddleware : ILetsEncryptChallengeApprovalMiddleware
{
    private const string MagicPrefix = "/.well-known/acme-challenge";
    private static readonly PathString MagicPrefixSegments = new(MagicPrefix);

    private readonly RequestDelegate _next;
    private readonly ILogger<ILetsEncryptChallengeApprovalMiddleware> _logger;
    private readonly IPersistenceService _persistenceService;

    public AcmeChallengeApprovalMiddleware(
        RequestDelegate next,
        ILogger<ILetsEncryptChallengeApprovalMiddleware> logger,
        IPersistenceService persistenceService)
    {
        _next = next;
        _logger = logger;
        _persistenceService = persistenceService;
    }

    public Task Invoke(HttpContext context)
    {
        return context.Request.Path.StartsWithSegments(MagicPrefixSegments)
            ? ProcessAcmeChallenge(context)
            : _next(context);
    }

    private async Task ProcessAcmeChallenge(HttpContext context)
    {
        var path = context.Request.Path.ToString();
        _logger.LogDebug(
            "Challenge invoked: {challengePath} by {IpAddress}",
            path,
            context.Connection.RemoteIpAddress);

        var requestedToken = path[$"{MagicPrefix}/".Length..];
        var allChallenges = await _persistenceService.GetPersistedChallenges();
        var matchingChallenge = allChallenges.FirstOrDefault(x => x.Token == requestedToken);
        if (matchingChallenge == null)
        {
            _logger.LogInformation(
                "The given challenge did not match {challengePath} among {allChallenges}",
                path,
                allChallenges);
            await _next(context);
            return;
        }

        // token response is always in ASCII so char count would be equal to byte count here
        context.Response.ContentLength = matchingChallenge.Response.Length;
        context.Response.ContentType = "application/octet-stream";
        await context.Response.WriteAsync(
            text: matchingChallenge.Response,
            cancellationToken: context.RequestAborted);
    }
}