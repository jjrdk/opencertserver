namespace OpenCertServer.Ca.Server;

using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Handlers;

public static class Extensions
{
    extension(IServiceCollection services)
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
        public IServiceCollection AddInMemoryCertificateStore()
        {
            return services.AddSingleton<IStoreCertificates>(new InMemoryCertificateStore());
        }

        /// <summary>
        /// Registers a certificate authority to the service collection with the provided configuration and optional chain validation function.
        /// </summary>
        /// <param name="configuration">The CA server configuration.</param>
        /// <param name="chainValidation">The <see cref="X509Chain"/> validation.</param>
        /// <returns>A configured <see cref="IServiceCollection"/>.</returns>
        public IServiceCollection AddCertificateAuthority(
            CaConfiguration configuration,
            IValidateX509Chains? chainValidation = null)
        {
            services.AddSingleton(configuration);
            services.AddSingleton(configuration.Profiles);
            services.AddSingleton<IValidateOcspRequest, OcspRequestSignatureValidator>();
            return services.AddSingleton<ICertificateAuthority>(sp =>
            {
                return new CertificateAuthority(
                    configuration,
                    sp.GetRequiredService<IStoreCertificates>(),
                    chainValidation ?? new ValidateAll(),
                    sp.GetRequiredService<ILogger<CertificateAuthority>>());
            });
        }

        /// <summary>
        /// Registers a self-signed certificate authority to the service collection with the provided
        /// <see cref="X500DistinguishedName"/> and optional OCSP and CA Issuers URLs.
        /// </summary>
        /// <param name="distinguishedName">The <see cref="X500DistinguishedName"/> of the server.</param>
        /// <param name="ocspUrls">The known OCSP responder URLs.</param>
        /// <param name="crlUrls">The known CRL distribution point URLs.</param>
        /// <param name="caIssuersUrls">The known CA issuer URLs.</param>
        /// <param name="certificateValidity">The duration of the issued certificates.</param>
        /// <param name="chainValidation">The <see cref="X509Chain"/> validation.</param>
        /// <param name="strictOcspHttpBinding">Whether to enforce strict OCSP HTTP binding, including content-type validation for POST requests.</param>
        /// <param name="ocspFreshnessWindow">The OCSP freshness window for responses.</param>
        /// <returns>A configured <see cref="IServiceCollection"/>.</returns>
        public IServiceCollection AddSelfSignedCertificateAuthority(
            X500DistinguishedName distinguishedName,
            string[]? ocspUrls = null,
            string[]? crlUrls = null,
            string[]? caIssuersUrls = null,
            TimeSpan certificateValidity = default,
            IValidateX509Chains? chainValidation = null,
            bool strictOcspHttpBinding = false,
            TimeSpan ocspFreshnessWindow = default)
        {
            var config = new CaConfiguration(
                new CaProfileSet(
                    "default",
                    CertificateAuthority.CreateSelfSignedRsa(
                        "default",
                        distinguishedName,
                        certificateValidity == TimeSpan.Zero ? TimeSpan.FromDays(90) : certificateValidity,
                        BigInteger.Zero,
                        ocspFreshnessWindow == TimeSpan.Zero ? TimeSpan.FromHours(1) : ocspFreshnessWindow),
                    CertificateAuthority.CreateSelfSignedEcdsa(
                        "ecdsa",
                        distinguishedName,
                        certificateValidity == TimeSpan.Zero ? TimeSpan.FromDays(90) : certificateValidity,
                        BigInteger.Zero,
                        ocspFreshnessWindow == TimeSpan.Zero ? TimeSpan.FromHours(1) : ocspFreshnessWindow)
                ),
                ocspUrls ?? [],
                crlUrls ?? [],
                caIssuersUrls ?? [],
                strictOcspHttpBinding);
            services.AddSingleton(config);
            services.AddSingleton(config.Profiles);
            services.AddSingleton<IValidateOcspRequest, OcspRequestSignatureValidator>();
            return services.AddSingleton<ICertificateAuthority>(sp =>
            {
                var certificateAuthority = new CertificateAuthority(
                    config,
                    sp.GetRequiredService<IStoreCertificates>(),
                    chainValidation ?? new ValidateAll(),
                    sp.GetRequiredService<ILogger<CertificateAuthority>>(),
                    validators: sp.GetServices<IValidateCertificateRequests>().ToArray());
                return certificateAuthority;
            });
        }
    }

    extension(IApplicationBuilder app)
    {
        /// <summary>
        /// <para>Registers the certificate authority server endpoints to the application's request pipeline.</para>
        /// <para>The OCSP endpoint of the certificate server requires a <see cref="IResponderId"/> service to be registered.</para>
        /// </summary>
        /// <returns>A configured <see cref="IApplicationBuilder"/>.</returns>
        public IApplicationBuilder UseCertificateAuthorityServer()
        {
            return app.UseRouting().UseEndpoints(endpoints => { endpoints.MapCertificateAuthorityServer(); });
        }
    }

    extension(IEndpointRouteBuilder endpoints)
    {
        /// <summary>
        /// <para>Maps the certificate authority server endpoints to the provided <see cref="IEndpointRouteBuilder"/>.</para>
        /// <para>The OCSP endpoint of the certificate server requires a <see cref="IResponderId"/> service to be registered.</para>
        /// </summary>
        /// <returns>A configured <see cref="IEndpointRouteBuilder"/>.</returns>
        public IEndpointRouteBuilder MapCertificateAuthorityServer()
        {
            var groupBuilder = endpoints.MapGroup("/ca");
            groupBuilder.MapPost("/csr", CsrHandler.Handle).RequireAuthorization(policy =>
            {
                policy.RequireAuthenticatedUser();
            });
            groupBuilder.MapGet("/inventory", InventoryHandler.Handle)
                .CacheOutput(cache => { cache.Expire(TimeSpan.FromHours(1)); }).AllowAnonymous();
            groupBuilder
                .MapDelete("/revoke", RevocationHandler.Handle).RequireAuthorization(policy =>
                {
                    policy.RequireAuthenticatedUser();
                });
            groupBuilder.MapGet("/crl", CrlHandler.Handle)
                .CacheOutput(cache => { cache.Expire(TimeSpan.FromHours(12)); }).AllowAnonymous();
            groupBuilder.MapGet("/{profileName}/crl", CrlHandler.HandleProfile)
                .CacheOutput(cache => { cache.Expire(TimeSpan.FromHours(12)); }).AllowAnonymous();
            groupBuilder.MapPost("/ocsp", OcspHandler.Handle).WithName("ocsp").AllowAnonymous();
            groupBuilder.MapGet("/ocsp/{requestEncoded}", OcspHandler.HandleGet).WithName("ocspGet").AllowAnonymous();
            groupBuilder.MapGet("/certificate", CertificateRetrievalHandler.HandleGet)
                .AllowAnonymous();
            return endpoints;
        }
    }
}

[JsonSerializable(typeof(CertificateItem))]
[JsonSerializable(typeof(CertificateItem[]))]
[JsonSerializable(typeof(CertificateItemInfo))]
[JsonSerializable(typeof(CertificateItemInfo[]))]
internal partial class CaServerSerializerContext : JsonSerializerContext
{
}
