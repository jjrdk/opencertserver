namespace OpenCertServer.Acme.Server.Middleware;

using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Builder;

public static class AcmeMiddlewareExtensions
{
    [RequiresUnreferencedCode("Uses AcmeMiddleware")]
    public static IApplicationBuilder UseAcmeServer(this IApplicationBuilder builder)
    {
        return builder.UseMiddleware<AcmeMiddleware>();
    }
}
