using CertesSlim.Json;
using OpenCertServer.Acme.Server.Extensions;

namespace OpenCertServer.Acme.Server.Filters;

using Abstractions.RequestServices;
using OpenCertServer.Acme.Abstractions.Exceptions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Routing;

public sealed class ValidateAcmeRequestFilter : IEndpointFilter
{
    private readonly IRequestValidationService _validationService;

    public ValidateAcmeRequestFilter(IRequestValidationService validationService)
    {
        _validationService = validationService;
    }

    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        if (context.HttpContext.Request.Method != HttpMethods.Post)
        {
            return await next(context).ConfigureAwait(false);
        }

        var payload = context.Arguments.OfType<JwsPayload>().FirstOrDefault();
        if (payload == null)
        {
            throw new MalformedRequestException("Invalid JWS payload.");
        }

        var acmeHeader = payload.ToAcmeHeader();
        var endpointName = context.HttpContext.GetEndpoint()?.Metadata.GetMetadata<IEndpointNameMetadata>()?.EndpointName;
        await _validationService.ValidateRequestAsync(payload, acmeHeader, context.HttpContext.Request.GetDisplayUrl(),
            context.HttpContext.Request.ContentType,
            endpointName,
            context.HttpContext.RequestAborted).ConfigureAwait(false);
        return await next(context).ConfigureAwait(false);
    }
}
