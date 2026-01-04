namespace OpenCertServer.Acme.Server.Middleware;

using System.Text.Json;
using Abstractions.HttpModel.Requests;
using Abstractions.RequestServices;
using Microsoft.AspNetCore.Http;

public sealed class AcmeMiddleware
{
    private readonly RequestDelegate _next;

    public AcmeMiddleware(RequestDelegate next)
    {
        _next = next;
    }

    public async Task InvokeAsync(HttpContext context, IAcmeRequestProvider requestProvider)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestProvider);

        if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasJsonContentType())
        {
            var result = await JsonSerializer.DeserializeAsync<AcmeRawPostRequest>(context.Request.Body,
                AcmeSerializerContext.Default.AcmeRawPostRequest);
            if (result != null)
            {
                requestProvider.Initialize(result);
            }
        }

        await _next(context);
    }
}
