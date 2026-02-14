using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;
using OpenCertServer.Acme.Abstractions.Services;

namespace OpenCertServer.Acme.Server.Endpoints;

public static partial class NonceEndpoints
{
    public static IEndpointRouteBuilder MapNonceEndpoints(this IEndpointRouteBuilder endpoints)
    {
        // HEAD /new-nonce
        endpoints.MapMethods("/new-nonce", ["HEAD"], async (HttpContext context, INonceService nonceService, ILogger<INonceService> logger) =>
        {
            await AddNonceHeader(context, nonceService, logger);
            context.Response.StatusCode = StatusCodes.Status200OK;
        })
        .WithName("NewNonce");

        // GET /new-nonce
        endpoints.MapGet("/new-nonce", async (HttpContext context, INonceService nonceService, ILogger<INonceService> logger) =>
        {
            await AddNonceHeader(context, nonceService, logger);
            context.Response.StatusCode = StatusCodes.Status204NoContent;
        });
//        .WithName("NewNonce");

        return endpoints;
    }

    private static async Task AddNonceHeader(HttpContext httpContext, INonceService nonceService, ILogger logger)
    {
        if (httpContext.Response.Headers.ContainsKey("Replay-Nonce"))
        {
            return;
        }

        var newNonce = await nonceService.CreateNonceAsync(httpContext.RequestAborted);
        httpContext.Response.Headers["Replay-Nonce"] = newNonce.Token;
        logger.LogAddedReplayNonceNonceToken(newNonce.Token);
    }

    [LoggerMessage(LogLevel.Information, "Added Replay-Nonce: {nonceToken}")]
    static partial void LogAddedReplayNonceNonceToken(this ILogger logger, string nonceToken);
}
