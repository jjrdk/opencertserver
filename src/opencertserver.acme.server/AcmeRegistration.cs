using Microsoft.AspNetCore.Http;
using OpenCertServer.Acme.Server.Endpoints;
using OpenCertServer.Acme.Server.Filters;

namespace OpenCertServer.Acme.Server;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;

public static class AcmeRegistration
{
    public static IApplicationBuilder UseAcmeServer(this IApplicationBuilder app, string pathBase = "")
    {
        return app.UseRouting().UseEndpoints(e => e.RegisterAcmeEndpoints(pathBase));
    }

    public static IEndpointRouteBuilder RegisterAcmeEndpoints(this IEndpointRouteBuilder app, string pathBase = "")
    {
        _ = app.MapGroup(pathBase).AddEndpointFilter<AcmeIndexLinkFilter>()
            .AddEndpointFilter<ValidateAcmeRequestFilter>()
            .MapDirectoryEndpoints().MapNonceEndpoints().MapAccountEndpoints().MapOrderEndpoints();
        return app;
    }
}
