using System.Text;
using Microsoft.AspNetCore.Http;
using OpenCertServer.Est.Server.Handlers;

namespace OpenCertServer.Est.Server.Response;

internal sealed class RetryAfterResult(TimeSpan retryAfter, string? message = null) : IResult
{
    public async Task ExecuteAsync(HttpContext httpContext)
    {
        httpContext.Response.StatusCode = StatusCodes.Status202Accepted;
        httpContext.Response.Headers.RetryAfter = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds)).ToString();

        if (!string.IsNullOrWhiteSpace(message))
        {
            httpContext.Response.ContentType = Constants.TextPlainMimeType;
            await httpContext.Response.WriteAsync(message, Encoding.UTF8).ConfigureAwait(false);
        }
    }
}

