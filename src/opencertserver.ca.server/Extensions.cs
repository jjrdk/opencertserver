using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using opencertserver.ca.server.Handlers;

namespace opencertserver.ca.server;

public static class Extensions
{
    extension(IApplicationBuilder app)
    {
        public IApplicationBuilder UseCertificateAuthorityServer()
        {
            return app.UseRouting().UseEndpoints(endpoints => { endpoints.MapCertificateAuthorityServer(); });
        }
    }

    extension(IEndpointRouteBuilder endpoints)
    {
        public IEndpointRouteBuilder MapCertificateAuthorityServer()
        {
            var groupBuilder = endpoints.MapGroup("/ca");
            groupBuilder
                .MapDelete("/revoke", RevocationHandler.Handle).RequireAuthorization(policy =>
                {
                    policy.RequireAuthenticatedUser();
                });
            groupBuilder.MapGet("/crl", CrlHandler.Handle)
                .CacheOutput(cache => { cache.Expire(TimeSpan.FromHours(12)); }).AllowAnonymous();
            return endpoints;
        }
    }
}
