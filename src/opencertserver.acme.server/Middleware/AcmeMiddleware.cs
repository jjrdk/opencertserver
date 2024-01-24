namespace OpenCertServer.Acme.Server.Middleware;

using System.Text.Json;
using System.Diagnostics.CodeAnalysis;
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

    [RequiresUnreferencedCode($"Uses {nameof(AcmeRawPostRequest)}")]
    [UnconditionalSuppressMessage("AOT",
        "IL3050:Calling members annotated with 'RequiresDynamicCodeAttribute' may break functionality when AOT compiling.",
        Justification = "Type is part of output signature")]
    public async Task InvokeAsync(HttpContext context, IAcmeRequestProvider requestProvider)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(requestProvider);

        if (HttpMethods.IsPost(context.Request.Method) && context.Request.HasJsonContentType())
        {
            var result = await JsonSerializer.DeserializeAsync<AcmeRawPostRequest>(context.Request.Body);
            if (result != null)
            {
                requestProvider.Initialize(result);
            }
        }

        await _next(context);
    }
}
