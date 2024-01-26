using Microsoft.AspNetCore.Authentication.Certificate;

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
using OpenCertServer.Ca;

/// <summary>
/// Defines the certificate server extension methods.
/// </summary>
public static class CertificateServerExtensions
{
    public static IServiceCollection AddEstServer(
        this IServiceCollection services,
        X500DistinguishedName distinguishedName,
        TimeSpan certificateValidity = default,
        Func<X509Chain, bool>? chainValidation = null)
    {
        services.AddSingleton<ICertificateAuthority>(
            sp =>
            {
                var certificateAuthority = new CertificateAuthority(
                    distinguishedName,
                    certificateValidity == default ? TimeSpan.FromDays(90) : certificateValidity,
                    chainValidation ?? (_ => true),
                    sp.GetRequiredService<ILogger<CertificateAuthority>>());
                return certificateAuthority;
            });

        return services.InnerAddEstServer();
    }

    public static IServiceCollection AddEstServer(
        this IServiceCollection services,
        X509Certificate2 rsaCertificate,
        X509Certificate2 ecdsaCertificate,
        Func<X509Chain, bool>? chainValidation = null)
    {
        if (rsaCertificate.PublicKey.Oid.Value != CertificateConstants.RsaOid)
        {
            throw new ArgumentException("Must be an RSA key certificate");
        }

        if (ecdsaCertificate.PublicKey.Oid.Value != CertificateConstants.EcdsaOid)
        {
            throw new ArgumentException("Must be an ECDSA key certificate");
        }

        return services.AddSingleton<ICertificateAuthority>(
                sp => new CertificateAuthority(
                    rsaCertificate,
                    ecdsaCertificate,
                    TimeSpan.FromDays(90),
                    chainValidation ?? (_ => true),
                    sp.GetRequiredService<ILogger<CertificateAuthority>>()))
            .InnerAddEstServer();
    }

    private static IServiceCollection InnerAddEstServer(this IServiceCollection services)
    {
        return services.AddTransient<CaCertHandler>()
            .AddTransient<SimpleEnrollHandler>()
            .AddTransient<SimpleReEnrollHandler>()
            .AddTransient<X509Certificate2Collection>(
                sp => sp.GetRequiredService<ICertificateAuthority>().GetRootCertificates());
    }

    public static IApplicationBuilder UseEstServer(
        this IApplicationBuilder app,
        IAuthorizeData? enrollPolicy = null,
        IAuthorizeData? reEnrollPolicy = null)
    {
        const string? wellKnownEst = "/.well-known/est";
        return app.UseCertificateForwarding()
            .UseAuthentication()
            .UseRouting()
            .UseAuthorization()
            .UseEndpoints(
                e =>
                {
                    e.MapGet(
                        $"{wellKnownEst}/cacert",
                        async ctx =>
                        {
                            var handler = ctx.RequestServices.GetRequiredService<CaCertHandler>();
                            await handler.Handle(ctx).ConfigureAwait(false);
                        });
                    var enrollBuilder = e.MapPost(
                        $"{wellKnownEst}/simpleenroll",
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

                    var reEnrollBuilder = e.MapPost(
                        $"{wellKnownEst}/simplereenroll",
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

    private static void ConfigurePolicy(AuthorizationPolicyBuilder b)
    {
        b.AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme, CertificateAuthenticationDefaults.AuthenticationScheme)
            .RequireAuthenticatedUser();
    }
}
