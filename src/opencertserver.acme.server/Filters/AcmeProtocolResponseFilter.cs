using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using OpenCertServer.Acme.Abstractions.Exceptions;
using OpenCertServer.Acme.Abstractions.HttpModel;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Server.Endpoints;

namespace OpenCertServer.Acme.Server.Filters;

public sealed class AcmeProtocolResponseFilter : IEndpointFilter
{
    private readonly INonceService _nonceService;
    private readonly ILogger<AcmeProtocolResponseFilter> _logger;

    public AcmeProtocolResponseFilter(INonceService nonceService, ILogger<AcmeProtocolResponseFilter> logger)
    {
        _nonceService = nonceService;
        _logger = logger;
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        try
        {
            var result = await next(context).ConfigureAwait(false);
            if (HttpMethods.IsPost(context.HttpContext.Request.Method))
            {
                await NonceEndpoints.EnsureReplayNonceHeaderAsync(context.HttpContext, _nonceService, _logger)
                    .ConfigureAwait(false);
            }

            return result;
        }
        catch (AcmeException ex)
        {
            return await CreateProblemResultAsync(context.HttpContext, ex, MapStatusCode(ex)).ConfigureAwait(false);
        }
        catch (JsonException ex)
        {
            return await CreateProblemResultAsync(
                    context.HttpContext,
                    new MalformedRequestException(ex.Message),
                    StatusCodes.Status400BadRequest)
                .ConfigureAwait(false);
        }
    }

    [UnconditionalSuppressMessage("Trimming", "IL2026",
        Justification = "ACME problem documents are small known DTOs and this server path is not trimmed in the test/runtime configuration.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "ACME problem responses are emitted in the regular ASP.NET runtime configuration used by this project.")]
    private async Task<IResult> CreateProblemResultAsync(HttpContext httpContext, AcmeException exception, int statusCode)
    {
        if (HttpMethods.IsPost(httpContext.Request.Method))
        {
            await NonceEndpoints.EnsureReplayNonceHeaderAsync(httpContext, _nonceService, _logger).ConfigureAwait(false);
        }

        // RFC 8555 §7.3.3: when the server rejects a request because the terms of service have
        // changed, the response MUST include a Link header pointing to the new terms of service.
        if (exception is UserActionRequiredException { TosUrl: { } tosUrl })
        {
            httpContext.Response.Headers.Append("Link", $"<{tosUrl}>; rel=\"terms-of-service\"");
        }

        var problem = new AcmeError($"{exception.UrnBase}:{exception.ErrorType}", exception.Message)
        {
            Status = statusCode
        };

        return Results.Json(problem, contentType: "application/problem+json", statusCode: statusCode);
    }

    private static int MapStatusCode(AcmeException exception)
    {
        return exception switch
        {
            AccountDoesNotExistException => StatusCodes.Status400BadRequest,
            BadCsrException => StatusCodes.Status400BadRequest,
            BadNonceException => StatusCodes.Status400BadRequest,
            BadSignatureAlgorithmException => StatusCodes.Status400BadRequest,
            ConflictRequestException => StatusCodes.Status409Conflict,
            NotFoundException => StatusCodes.Status404NotFound,
            NotAllowedException => StatusCodes.Status403Forbidden,
            NotAuthorizedException => StatusCodes.Status403Forbidden,
            UserActionRequiredException => StatusCodes.Status403Forbidden,
            _ => StatusCodes.Status400BadRequest
        };
    }
}


