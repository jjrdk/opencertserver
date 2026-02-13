using System.Text.Json;
using CertesSlim.Json;
using OpenCertServer.Acme.Abstractions.HttpModel.Requests;
using OpenCertServer.Acme.Server.Extensions;

namespace OpenCertServer.Acme.Server.Filters;

using Abstractions.RequestServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc.Filters;

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
            return await next(context);
        }

        var payload = context.Arguments.OfType<JwsPayload>().FirstOrDefault();
        if (payload == null)
        {
            throw new ArgumentException("Invalid JWS payload");
        }

        var acmeHeader = payload.ToAcmeHeader();
        await _validationService.ValidateRequestAsync(payload, acmeHeader, context.HttpContext.Request.GetDisplayUrl(),
            context.HttpContext.RequestAborted);
        return await next(context);
    }
}
