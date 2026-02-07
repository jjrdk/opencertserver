using OpenCertServer.Ca.Utils;
using OpenCertServer.Ca.Utils.Ca;

namespace OpenCertServer.Est.Server;

using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using Ca;
using Handlers;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Defines the certificate server extension methods.
/// </summary>
public static class EstServerExtensions
{
    /// <summary>
    /// <para>
    /// Registers an in-memory certificate store to the service collection.
    /// </para>
    /// <para>
    /// This is useful for testing and development purposes, but should not be used in production environments.
    /// </para>
    /// </summary>
    /// <returns>A configured <see cref="IServiceCollection"/>.</returns>
    extension(IServiceCollection services)
    {
        public IServiceCollection AddEstServer<
                [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
                TCsrAttrs>()
            where TCsrAttrs : CsrAttributesHandler
        {
            return services
                .InnerAddEstServer<TCsrAttrs>();
        }

        private IServiceCollection InnerAddEstServer<
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TCsrAttrs>()
            where TCsrAttrs : CsrAttributesHandler
        {
            return services
                .AddScoped<CsrAttributesHandler, TCsrAttrs>()
                .AddTransient<ServerKeyGenHandler>()
                .AddTransient<CaCertHandler>()
                .AddTransient<SimpleEnrollHandler>()
                .AddTransient<SimpleReEnrollHandler>()
                .AddTransient<X509Certificate2Collection>(sp =>
                    sp.GetRequiredService<ICertificateAuthority>().GetRootCertificates());
        }
    }

    extension(IApplicationBuilder app)
    {
        /// <summary>
        /// Registers the EST server middleware.
        /// </summary>
        /// <param name="enrollPolicy">The <see cref="AuthorizationPolicy"/> to apply to enrollment requests.</param>
        /// <param name="reEnrollPolicy">The <see cref="AuthorizationPolicy"/> to apply to re-enrollment requests.</param>
        /// <param name="csrAttrsPolicy">The <see cref="AuthorizationPolicy"/> to apply to CSR template requests.</param>
        /// <param name="serverKeyGenPolicy">The <see cref="AuthorizationPolicy"/> to apply to server keygen requests.</param>
        /// <returns></returns>
        public IApplicationBuilder UseEstServer(
            AuthorizationPolicy? enrollPolicy = null,
            AuthorizationPolicy? reEnrollPolicy = null,
            AuthorizationPolicy? csrAttrsPolicy = null,
            AuthorizationPolicy? serverKeyGenPolicy = null)
        {
            return app.UseCertificateForwarding()
                .UseRouting()
                .UseAuthentication()
                .UseAuthorization()
                .UseEndpoints(e =>
                {
                    e.MapEstServer(enrollPolicy, reEnrollPolicy, csrAttrsPolicy, serverKeyGenPolicy);
                });
        }
    }

    extension(IEndpointRouteBuilder endpoints)
    {
        /// <summary>
        /// Maps the EST server endpoints as defined in RFC 3070.
        /// </summary>
        /// <param name="enrollPolicy">The <see cref="AuthorizationPolicy"/> to apply to enrollment requests.</param>
        /// <param name="reEnrollPolicy">The <see cref="AuthorizationPolicy"/> to apply to re-enrollment requests.</param>
        /// <param name="csrAttrsPolicy">The <see cref="AuthorizationPolicy"/> to apply to CSR template requests.</param>
        /// <param name="serverKeyGenPolicy">The <see cref="AuthorizationPolicy"/> to apply to server keygen requests.</param>
        /// <returns>A configured <see cref="IEndpointRouteBuilder"/></returns>
        public IEndpointRouteBuilder MapEstServer(
            AuthorizationPolicy? enrollPolicy = null,
            AuthorizationPolicy? reEnrollPolicy = null,
            AuthorizationPolicy? csrAttrsPolicy = null,
            AuthorizationPolicy? serverKeyGenPolicy = null)
        {
            const string? wellKnownEst = "/.well-known/est";
            var groupBuilder = endpoints.MapGroup(wellKnownEst);
            groupBuilder.MapGet("/serverkeygen", async ctx =>
            {
                var handler = ctx.RequestServices.GetRequiredService<ServerKeyGenHandler>();
                await handler.Handle(ctx);
            }).RequireAuthorization(serverKeyGenPolicy ?? ConfigurePolicy());
            groupBuilder.MapGet(
                "/csrattrs",
                async ctx =>
                {
                    var handler = ctx.RequestServices.GetRequiredService<CsrAttributesHandler>();
                    await handler.Handle(ctx).ConfigureAwait(false);
                }).RequireAuthorization(csrAttrsPolicy ?? ConfigurePolicy());
            groupBuilder.MapGet(
                    "/cacert",
                    async ctx =>
                    {
                        var handler = ctx.RequestServices.GetRequiredService<CaCertHandler>();
                        await handler.Handle(ctx).ConfigureAwait(false);
                    })
                .CacheOutput(b => b.Cache().Expire(TimeSpan.FromDays(30)))
                .AllowAnonymous();
            groupBuilder.MapPost(
                "/simpleenroll",
                async ctx =>
                {
                    var handler = ctx.RequestServices.GetRequiredService<SimpleEnrollHandler>();
                    await handler.Handle(ctx).ConfigureAwait(false);
                }).RequireAuthorization(enrollPolicy ?? ConfigurePolicy());

            groupBuilder.MapPost(
                "/simplereenroll",
                async ctx =>
                {
                    var handler = ctx.RequestServices.GetRequiredService<SimpleReEnrollHandler>();
                    await handler.Handle(ctx).ConfigureAwait(false);
                }).RequireAuthorization(reEnrollPolicy ?? ConfigurePolicy());

            return endpoints;
        }
    }

    private static AuthorizationPolicy ConfigurePolicy()
    {
        return new AuthorizationPolicyBuilder().AddAuthenticationSchemes(
                JwtBearerDefaults.AuthenticationScheme,
                CertificateAuthenticationDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser().Build();
    }
}
