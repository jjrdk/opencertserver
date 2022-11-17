namespace OpenCertServer.Acme.Server.Middleware;

using Microsoft.AspNetCore.Builder;

public static class AcmeMiddlewareExtensions
{
    public static IApplicationBuilder UseAcmeServer(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<AcmeMiddleware>().UseRouting().UseEndpoints(e=>e.MapControllers());
    }
}