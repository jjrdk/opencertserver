namespace OpenCertServer.Acme.Server.Middleware
{
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
                var result = await context.Request.ReadAcmeRequest();
                if (result != null)
                {
                    requestProvider.Initialize(result);
                }
            }

            await _next(context);
        }
    }
}
