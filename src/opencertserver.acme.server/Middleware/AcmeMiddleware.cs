namespace OpenCertServer.Acme.Server.Middleware
{
    using System.Text.Json;
    using Abstractions.HttpModel.Requests;
    using Abstractions.RequestServices;
    using Microsoft.AspNetCore.Http;

    public class AcmeMiddleware
    {
        private readonly RequestDelegate _next;

        public AcmeMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IAcmeRequestProvider requestProvider)
        {
            if (context is null)
            {
                throw new ArgumentNullException(nameof(context));
            }

            if (requestProvider is null)
            {
                throw new ArgumentNullException(nameof(requestProvider));
            }

            if (HttpMethods.IsPost(context.Request.Method))
            {
                var result = await context.Request.ReadAcmeRequest() ?? throw new BadHttpRequestException("Invalid content");
                requestProvider.Initialize(result);
            }

            await _next(context);
        }
    }

    public static class AcmeRequestReader
    {
        public static async Task<AcmeRawPostRequest?> ReadAcmeRequest(this HttpRequest request)
        {
            var result = await JsonSerializer.DeserializeAsync<AcmeRawPostRequest>(request.Body);
            return result;
        }
    }
}
