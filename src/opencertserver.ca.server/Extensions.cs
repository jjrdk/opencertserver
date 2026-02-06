namespace OpenCertServer.Ca.Server;

using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Handlers;

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
            groupBuilder.MapGet("/inventory", InventoryHandler.Handle)
                .CacheOutput(cache => { cache.Expire(TimeSpan.FromHours(1)); }).AllowAnonymous();
            groupBuilder
                .MapDelete("/revoke", RevocationHandler.Handle).RequireAuthorization(policy =>
                {
                    policy.RequireAuthenticatedUser();
                });
            groupBuilder.MapGet("/crl", CrlHandler.Handle)
                .CacheOutput(cache => { cache.Expire(TimeSpan.FromHours(12)); }).AllowAnonymous();
            groupBuilder.MapPost("/ocsp", OcspHandler.Handle).AllowAnonymous();
            groupBuilder.MapGet("/certificate", CertificateRetrievalHandler.HandleGet)
                .AllowAnonymous();
            return endpoints;
        }
    }
}

[JsonSerializable(typeof(CertificateItem))]
[JsonSerializable(typeof(CertificateItem[]))]
internal partial class CaServerSerializerContext : JsonSerializerContext
{
}
