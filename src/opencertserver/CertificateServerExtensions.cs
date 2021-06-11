namespace OpenCertServer.Est
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using Ca;
    using Handlers;
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Builder;
    using Microsoft.Extensions.DependencyInjection;
    using Microsoft.Extensions.Logging;

    /// <summary>
    /// Defines the certificate server extension methods.
    /// </summary>
    public static class CertificateServerExtensions
    {
        private const string RsaOid = "1.2.840.113549.1.1.1";
        private const string EcdsaOid = "1.2.840.10045.2.1";

        public static IServiceCollection AddCertificateServer(
            this IServiceCollection services,
            X509Certificate2 rsaCertificate,
            X509Certificate2 ecdsaCertificate,
            Func<X509Chain, bool>? chainValidation = null)
        {
            if (rsaCertificate.PublicKey.Oid.Value != RsaOid)
            {
                throw new ArgumentException("Must be an RSA key certificate");
            }

            if (ecdsaCertificate.PublicKey.Oid.Value != EcdsaOid)
            {
                throw new ArgumentException("Must be an ECDSA key certificate");
            }

            var collection = new X509Certificate2Collection { rsaCertificate, ecdsaCertificate, };

            services.AddSingleton(collection);
            services.AddTransient<CaCertHandler>()
                .AddTransient<SimpleEnrollHandler>()
                .AddTransient<SimpleReEnrollHandler>();
            services.AddSingleton<ICertificateAuthority>(
                sp => new CertificateAuthority(
                    rsaCertificate,
                    ecdsaCertificate,
                    TimeSpan.FromDays(90),
                    chainValidation ?? (_ => true),
                    sp.GetRequiredService<ILogger<CertificateAuthority>>(),
                    new OwnCertificateValidation(
                        sp.GetRequiredService<X509Certificate2Collection>(),
                        sp.GetRequiredService<ILogger<OwnCertificateValidation>>()),
                    new DistinguishedNameValidation()));
            services.AddCertificateForwarding(
                o => { o.HeaderConverter = x => new X509Certificate2(Convert.FromBase64String(x)); });

            services.AddRouting();
            return services;
        }

        public static IApplicationBuilder UseCertificateServer(this IApplicationBuilder app, IAuthorizeData? enrollPolicy = null, IAuthorizeData? reEnrollPolicy = null)
        {
            const string? wellKnownEst = "/.well-known/est";
            return app.UseCertificateForwarding()
                .UseRouting()
                .UseAuthentication()
                .UseAuthorization()
                .UseEndpoints(
                    e =>
                    {
                        e.MapGet(
                            wellKnownEst + "/cacert",
                            async ctx =>
                            {
                                var handler = ctx.RequestServices.GetRequiredService<CaCertHandler>();
                                await handler.Handle(ctx).ConfigureAwait(false);
                            });
                        var enrollBuilder = e.MapPost(
                            wellKnownEst + "/simpleenroll",
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
                            enrollBuilder.RequireAuthorization();
                        }
                        var reEnrollBuilder = e.MapPost(
                                 wellKnownEst + "/simplereenroll",
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
                            reEnrollBuilder.RequireAuthorization();
                        }
                    });
        }
    }
}
