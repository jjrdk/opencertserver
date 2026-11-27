using OpenCertServer.Ca.Protocol;

namespace OpenCertServer.Ca.Server;

using System.Numerics;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Utils.Ca;
using Utils.Ocsp;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Handlers;
using OpenCertServer.Ca.Server.PublicRa;
using OpenCertServer.Ca.Server.RegistrationAuthority;

public static class Extensions
{
    /// <param name="services">The service collection.</param>
    extension(IServiceCollection services)
    {
        /// <summary>
        /// Enables the opt-in public ACME self-service validator.
        /// ACME remains responsible for challenge validation and CSR proof-of-possession.
        /// </summary>
        public IServiceCollection AddPublicRa(IConfiguration configuration)
        {
            return services.AddPublicRa(PublicRaOptions.FromConfiguration(configuration));
        }

        /// <summary>
        /// Enables the opt-in public ACME self-service validator.
        /// </summary>
        public IServiceCollection AddPublicRa(PublicRaOptions options)
        {
            if (options.RateLimit < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(options), "PublicRa rate limit must be at least one.");
            }

            if (options is { Enabled: true, Profiles.Count: 0 })
            {
                throw new InvalidOperationException(
                    "PublicRa:Profiles must list at least one profile when public enrollment is enabled.");
            }

            if (options is { Enabled: true, RequireApproval: true })
            {
                throw new InvalidOperationException(
                    "PublicRa:RequireApproval is not supported until the certificate approval workflow is available.");
            }

            services.AddSingleton(options);
            if (options.Enabled)
            {
                services.TryAddEnumerable(
                    ServiceDescriptor.Singleton<IValidateCertificateRequests, PublicRaValidation>());
            }

            return services;
        }

        /// <summary>
        /// Registers the CA-side RA bindings from configuration.
        /// </summary>
        public IServiceCollection AddRa(IConfiguration configuration)
        {
            return services.AddRa(RaServerOptions.FromConfiguration(configuration));
        }

        /// <summary>
        /// Registers the CA-side RA bindings.
        /// </summary>
        public IServiceCollection AddRa(RaServerOptions options)
        {
            services.AddSingleton(options);
            services.TryAddSingleton<IStoreRas>(_ => new InMemoryRaStore(options.Bindings));
            services.TryAddSingleton<IValidateCertificateRequests, RaScopeValidator>();
            services.TryAddSingleton<IValidateCertificateRequests, RaRevocationValidator>();
            return services;
        }

        /// <summary>
        /// Registers an in-memory certificate store to the service collection.
        ///
        /// This is useful for testing and development purposes, but should not be used in production environments.
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
        /// <param name="certificateIdGenerator">The certificate ID generator.</param>
        /// <returns>A configured <see cref="IServiceCollection"/>.</returns>
        public IServiceCollection AddCertificateAuthority(
            CaConfiguration configuration,
            IValidateX509Chains? chainValidation = null,
            IGenerateCertificateId? certificateIdGenerator = null)
        {
            return services.AddSingleton(configuration)
                .AddSingleton(configuration.Profiles)
                .RegisterCaDependencies()
                .AddSingleton<ICertificateAuthority>(sp => new CertificateAuthority(
                    configuration,
                    sp.GetRequiredService<IStoreCertificates>(),
                    chainValidation ?? new ValidateAll(),
                    certificateIdGenerator ?? new RandomNumberCertificateIdGenerator(),
                    sp.GetRequiredService<ILogger<CertificateAuthority>>(),
                    sp.GetRequiredService<IValidatorPipeline>()));
        }

        /// <summary>
        /// Registers a certificate authority to the service collection with the provided configuration loader and
        /// optional chain validation function.
        /// </summary>
        /// <param name="configurationFactory">The configuration loader</param>
        /// <param name="chainValidation">The <see cref="X509Chain"/> validation.</param>
        /// <param name="certificateIdGenerator">The certificate ID generator.</param>
        /// <returns>A configured <see cref="IServiceCollection"/>.</returns>
        public IServiceCollection AddCertificateAuthority(
            Func<IServiceProvider, CaConfiguration> configurationFactory,
            IValidateX509Chains? chainValidation = null,
            IGenerateCertificateId? certificateIdGenerator = null)
        {
            return services.AddSingleton(configurationFactory)
                .AddTransient(sp => sp.GetRequiredService<CaConfiguration>().Profiles)
                .RegisterCaDependencies()
                .AddSingleton<ICertificateAuthority>(sp => new CertificateAuthority(
                    sp.GetRequiredService<CaConfiguration>(),
                    sp.GetRequiredService<IStoreCertificates>(),
                    chainValidation ?? new ValidateAll(),
                    certificateIdGenerator ?? new RandomNumberCertificateIdGenerator(),
                    sp.GetRequiredService<ILogger<CertificateAuthority>>(),
                    sp.GetRequiredService<IValidatorPipeline>()));
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
        /// <param name="certificateIdGenerator">The certificate ID generator.</param>
        /// <param name="strictOcspHttpBinding">Whether to enforce strict OCSP HTTP binding, including content-type validation for POST requests.</param>
        /// <param name="ocspFreshnessWindow">The OCSP freshness window for responses.</param>
        /// <param name="allowPublicEnrollment">Whether to allow public enrollment.</param>
        /// <returns>A configured <see cref="IServiceCollection"/>.</returns>
        public IServiceCollection AddSelfSignedCertificateAuthority(
            X500DistinguishedName distinguishedName,
            string[]? ocspUrls = null,
            string[]? crlUrls = null,
            string[]? caIssuersUrls = null,
            TimeSpan certificateValidity = default,
            IValidateX509Chains? chainValidation = null,
            IGenerateCertificateId? certificateIdGenerator = null,
            bool strictOcspHttpBinding = false,
            TimeSpan ocspFreshnessWindow = default,
            bool allowPublicEnrollment = false)
        {
            var validity = certificateValidity == TimeSpan.Zero
                ? TimeSpan.FromDays(90)
                : certificateValidity;
            var freshness = ocspFreshnessWindow == TimeSpan.Zero
                ? TimeSpan.FromHours(1)
                : ocspFreshnessWindow;
            var rsaProfile = CertificateAuthority.CreateSelfSignedRsa(
                    "default", distinguishedName, validity, BigInteger.Zero, freshness)
                with
            {
                AllowPublicEnrollment = allowPublicEnrollment
            };
            var ecdsaProfile = CertificateAuthority.CreateSelfSignedEcdsa(
                    "ecdsa", distinguishedName, validity, BigInteger.Zero, freshness)
                with
            {
                AllowPublicEnrollment = allowPublicEnrollment
            };
            var config = new CaConfiguration(
                new CaProfileSet(
                    "default",
                    rsaProfile,
                    ecdsaProfile
                ),
                ocspUrls ?? [],
                crlUrls ?? [],
                caIssuersUrls ?? [],
                strictOcspHttpBinding);
            return services.AddSingleton(config)
                .AddSingleton(config.Profiles)
                .RegisterCaDependencies()
                .AddSingleton<ICertificateAuthority>(sp =>
                {
                    var logger = sp.GetRequiredService<ILogger<CertificateAuthority>>();
                    var certificateAuthority = new CertificateAuthority(
                        config,
                        sp.GetRequiredService<IStoreCertificates>(),
                        chainValidation ?? new ValidateAll(),
                        certificateIdGenerator ?? new RandomNumberCertificateIdGenerator(),
                        logger,
                        sp.GetRequiredService<IValidatorPipeline>());
                    return certificateAuthority;
                });
        }

        private IServiceCollection RegisterCaDependencies()
        {
            services.AddSingleton<IValidateOcspRequest, OcspRequestSignatureValidator>();
            services.AddSingleton<IValidateCertificateRequests, CaExtensionValidation>();
            services.AddSingleton<IValidateCertificateRequests, OwnCertificateValidation>();
            services.AddSingleton<IValidateCertificateRequests, DistinguishedNameValidation>();
            services.AddSingleton<IValidateCertificateRequests, KeyCrlSignatureValidation>();
            services.AddSingleton<IValidateCertificateRequests, AuthenticatedSubjectValidation>();
            services.AddSingleton<ICertificateRequestValueConverter, AuthenticatedSubjectRequestValueConverter>();

            // Assemble the phased validator pipeline (T09) from the registered request validators. The five historical
            // validators run in the Issuance phase in registration order, in aggregate (run-all, join-errors) mode, so
            // behaviour is unchanged; operators can add more validators via AddValidator<T> or disable one via config.
            services.AddValidatorPipeline();
            return services;
        }

        /// <summary>
        /// Registers the default authorization policy for the certificate revocation endpoint.
        /// The policy requires an authenticated user; operators may supply an additional configure action
        /// to impose further restrictions (e.g. requiring a specific scheme or claim).
        /// Call this method before <see cref="MapCertificateAuthorityServer"/>.
        /// </summary>
        /// <param name="configureRevocationPolicy">
        /// Optional additional configuration applied on top of <c>RequireAuthenticatedUser()</c>.
        /// </param>
        /// <returns>The same <see cref="IServiceCollection"/> for chaining.</returns>
        public IServiceCollection AddCertificateAuthorityAuthorization(
            Action<AuthorizationPolicyBuilder>? configureRevocationPolicy = null)
        {
            return services.AddAuthorization(options =>
            {
                options.AddPolicy(RevocationAuthorizationConstants.RevocationPolicyName, policy =>
                {
                    policy.RequireAuthenticatedUser();
                    configureRevocationPolicy?.Invoke(policy);
                });
            });
        }
    }

    /// <summary>
    /// Registers the certificate authority server endpoints to the application's request pipeline.
    /// The OCSP endpoint of the certificate server requires a <see cref="IResponderId"/> service to be registered.
    /// </summary>
    /// <returns>A configured <see cref="IApplicationBuilder"/>.</returns>
    public static IApplicationBuilder UseCertificateAuthorityServer(this IApplicationBuilder app)
    {
        return app.UseRouting().UseEndpoints(endpoints => { endpoints.MapCertificateAuthorityServer(); });
    }

    /// <summary>
    /// Maps the certificate authority server endpoints to the provided <see cref="IEndpointRouteBuilder"/>.
    /// The OCSP endpoint of the certificate server requires a <see cref="IResponderId"/> service to be registered.
    /// </summary>
    /// <returns>A configured <see cref="IEndpointRouteBuilder"/>.</returns>
    public static IEndpointRouteBuilder MapCertificateAuthorityServer(this IEndpointRouteBuilder endpoints)
    {
        var groupBuilder = endpoints.MapGroup("/ca");
        groupBuilder.MapPost("/csr", CsrHandler.Handle).RequireAuthorization(policy =>
        {
            policy.RequireAuthenticatedUser();
        });
        groupBuilder.MapPost("/{profileName}/csr", CsrHandler.HandleProfile).RequireAuthorization(policy =>
        {
            policy.RequireAuthenticatedUser();
        });
        groupBuilder.MapGet("/profiles", ProfilesHandler.Handle).RequireAuthorization(policy =>
        {
            policy.RequireAuthenticatedUser();
        });
        groupBuilder
            .MapDelete("/revoke", RevocationHandler.Handle)
            .RequireAuthorization(RevocationAuthorizationConstants.RevocationPolicyName);
        groupBuilder.MapGet("/crl", CrlHandler.Handle)
            .CacheOutput(cache => { cache.Expire(TimeSpan.FromHours(12)); }).AllowAnonymous();
        groupBuilder.MapGet("/{profileName}/crl", CrlHandler.HandleProfile)
            .CacheOutput(cache => { cache.Expire(TimeSpan.FromHours(12)); }).AllowAnonymous();
        groupBuilder.MapGet("/published", PublishedCertificatesHandler.Handle)
            .RequireAuthorization(policy => { policy.RequireAuthenticatedUser(); });
        groupBuilder.MapGet("/{profileName}/published", PublishedCertificatesHandler.HandleProfile)
            .RequireAuthorization(policy => { policy.RequireAuthenticatedUser(); });
        groupBuilder.MapPost("/ocsp", OcspHandler.Handle).WithName("ocsp").AllowAnonymous();
        groupBuilder.MapGet("/ocsp/{**requestEncoded}", OcspHandler.HandleGet).WithName("ocspGet").AllowAnonymous();

        return endpoints;
    }
}
