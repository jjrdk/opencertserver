using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;

namespace OpenCertServer.Est.Server;

using System;
using System.Security.Cryptography.X509Certificates;
using Ca.Utils;
using Handlers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Ca;

/// <summary>
/// Defines the certificate server extension methods.
/// </summary>
public static class CertificateServerExtensions
{
    extension(IServiceCollection services)
    {
        public IServiceCollection AddInMemoryEstServer(
            X500DistinguishedName distinguishedName,
            TimeSpan certificateValidity = default,
            string[]? ocspUrls = null,
            string[]? caIssuersUrls = null,
            Func<X509Chain, bool>? chainValidation = null)
        {
            services.AddSingleton<Func<X509Certificate2, IStoreCertificates>>(_ =>
                c => new InMemoryCertificateStore(c));

            return services.AddEstServer(
                distinguishedName,
                ocspUrls,
                caIssuersUrls,
                certificateValidity,
                chainValidation);
        }

        public IServiceCollection AddEstServer(
            X500DistinguishedName distinguishedName,
            string[]? ocspUrls = null,
            string[]? caIssuersUrls = null,
            TimeSpan certificateValidity = default,
            Func<X509Chain, bool>? chainValidation = null)
        {
            services.AddSingleton<ICertificateAuthority>(sp =>
            {
                var certificateAuthority = CertificateAuthority.Create(
                    distinguishedName,
                    sp.GetRequiredService<Func<X509Certificate2, IStoreCertificates>>(),
                    certificateValidity == TimeSpan.Zero ? TimeSpan.FromDays(90) : certificateValidity,
                    ocspUrls ?? [],
                    caIssuersUrls ?? [],
                    sp.GetRequiredService<ILogger<CertificateAuthority>>(),
                    chainValidation);
                return certificateAuthority;
            });

            return services.InnerAddEstServer();
        }

        public IServiceCollection AddEstServer(
            CaConfiguration configuration,
            Func<X509Chain, bool>? chainValidation = null)
        {
            if (configuration.RsaCertificate.PublicKey.Oid.Value != Oids.Rsa)
            {
                throw new ArgumentException("Must be an RSA key certificate");
            }

            if (configuration.EcdsaCertificate.PublicKey.Oid.Value != Oids.EcPublicKey)
            {
                throw new ArgumentException("Must be an ECDSA key certificate");
            }

            return services.AddSingleton<ICertificateAuthority>(sp => new CertificateAuthority(
                    configuration,
                    sp.GetRequiredService<IStoreCertificates>(),
                    chainValidation ?? (_ => true),
                    sp.GetRequiredService<ILogger<CertificateAuthority>>()))
                .InnerAddEstServer();
        }

        private IServiceCollection InnerAddEstServer()
        {
            return services.AddTransient<CaCertHandler>()
                .AddTransient<SimpleEnrollHandler>()
                .AddTransient<SimpleReEnrollHandler>()
                .AddTransient<X509Certificate2Collection>(sp =>
                    sp.GetRequiredService<ICertificateAuthority>().GetRootCertificates());
        }
    }

    extension(IApplicationBuilder app)
    {
        public IApplicationBuilder UseEstServer(
            IAuthorizeData? enrollPolicy = null,
            IAuthorizeData? reEnrollPolicy = null)
        {
            const string? wellKnownEst = "/.well-known/est";
            return app.UseCertificateForwarding()
                .UseAuthentication()
                .UseRouting()
                .UseAuthorization()
                .UseEndpoints(e =>
                {
                    var groupBuilder = e.MapGroup(wellKnownEst);
                    groupBuilder.MapGet(
                        "/cacert",
                        async ctx =>
                        {
                            var handler = ctx.RequestServices.GetRequiredService<CaCertHandler>();
                            await handler.Handle(ctx).ConfigureAwait(false);
                        });
                    var enrollBuilder = groupBuilder.MapPost(
                        "/simpleenroll",
                        async ctx =>
                        {
                            var handler = ctx.RequestServices.GetRequiredService<SimpleEnrollHandler>();
                            await handler.Handle(ctx).ConfigureAwait(false);
                        });
                    if (enrollPolicy != null)
                    {
                        enrollBuilder.RequireAuthorization(enrollPolicy);
                    }
                    else
                    {
                        enrollBuilder.RequireAuthorization(ConfigurePolicy);
                    }

                    var reEnrollBuilder = groupBuilder.MapPost(
                        "/simplereenroll",
                        async ctx =>
                        {
                            var handler = ctx.RequestServices.GetRequiredService<SimpleReEnrollHandler>();
                            await handler.Handle(ctx).ConfigureAwait(false);
                        });
                    if (reEnrollPolicy != null)
                    {
                        reEnrollBuilder.RequireAuthorization(reEnrollPolicy);
                    }
                    else
                    {
                        reEnrollBuilder.RequireAuthorization(ConfigurePolicy);
                    }
                });
        }
    }

    private static void ConfigurePolicy(AuthorizationPolicyBuilder b)
    {
        b.AddAuthenticationSchemes(
                JwtBearerDefaults.AuthenticationScheme,
                CertificateAuthenticationDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser();
    }
}
