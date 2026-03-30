using System.Net;
using Microsoft.AspNetCore.Http;

namespace OpenCertServer.Est.Server.Handlers;

internal class MultipartContentResult : IResult
{
    private readonly MultipartContent _content;
    private readonly string _contentType;
    private readonly HttpStatusCode _statusCode;

    public MultipartContentResult(
        MultipartContent content,
        string contentType = Constants.MultiPartMixed,
        HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        _content = content;
        _contentType = contentType;
        _statusCode = statusCode;
    }

    public async Task ExecuteAsync(HttpContext ctx)
    {
        ctx.Response.StatusCode = (int)_statusCode;
        ctx.Response.ContentType = _contentType;
        await _content.CopyToAsync(ctx.Response.Body, ctx.RequestAborted).ConfigureAwait(false);
        await ctx.Response.Body.FlushAsync(ctx.RequestAborted).ConfigureAwait(false);
    }
}
