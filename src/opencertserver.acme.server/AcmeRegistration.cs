namespace OpenCertServer.Acme.Server;

using Microsoft.AspNetCore.Http;
using OpenCertServer.Acme.Server.Endpoints;
using OpenCertServer.Acme.Server.Filters;

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
        // ACME authenticates requests via JWS, not ASP.NET authentication; stay reachable under any fallback policy.
        _ = app.MapGroup(pathBase).AllowAnonymous().AddEndpointFilter<AcmeProtocolResponseFilter>()
            .AddEndpointFilter<AcmeIndexLinkFilter>()
            .AddEndpointFilter<ValidateAcmeRequestFilter>()
            .MapDirectoryEndpoints().MapNonceEndpoints().MapAccountEndpoints().MapOrderEndpoints().MapRevocationEndpoints();
        return app;
    }
}