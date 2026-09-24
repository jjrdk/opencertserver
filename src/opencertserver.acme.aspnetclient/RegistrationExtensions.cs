using System.Runtime.CompilerServices;
using OpenCertServer.Acme.Abstractions.AcmeRoute;

[assembly: InternalsVisibleTo("opencertserver.acme.aspnetclient.tests")]
[assembly: InternalsVisibleTo("opencertserver.certserver.tests")]
[assembly: InternalsVisibleTo("opencertserver.acme.yarp.tests")]

namespace OpenCertServer.Acme.AspNetClient;

using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenCertServer.Acme.AspNetClient.Certes;
using OpenCertServer.Acme.AspNetClient.Certificates;
using OpenCertServer.Acme.AspNetClient.Persistence;

public static class RegistrationExtensions
{
    extension(IServiceCollection services)
    {
        private IServiceCollection AddAcmePersistenceService()
        {
            return services.Any(x => x.ServiceType == typeof(IPersistenceService))
                ? services
                : services.AddSingleton<IPersistenceService, PersistenceService>();
        }

        private IServiceCollection AddAcmeRouteConfigurationSource()
        {
            return services.Any(x => x.ServiceType == typeof(IAcmeRouteConfigurationSource))
                ? services
                : services.AddSingleton<IAcmeRouteConfigurationSource>(
                    new InMemoryAcmeRouteConfigurationSource(Array.Empty<IAcmeRouteConfiguration>()));
        }

        public IServiceCollection AddAcmeRenewalLifecycleHook<
            [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
            TCertificateRenewalLifecycleHook>()
            where TCertificateRenewalLifecycleHook : class, ICertificateRenewalLifecycleHook
        {
            return services.AddAcmePersistenceService()
                .AddSingleton<ICertificateRenewalLifecycleHook, TCertificateRenewalLifecycleHook>();
        }

        public IServiceCollection AddAcmeCertificatePersistence(
            Func<CertificateType, byte[], Task> persistAsync,
            Func<CertificateType, Task<byte[]?>> retrieveAsync)
        {
            return services.AddAcmeCertificatePersistence(
                new CustomCertificatePersistenceStrategy(persistAsync, retrieveAsync));
        }

        /// <summary>
        /// Registers a route-aware custom persistence strategy that supports per-route certificate
        /// storage and per-route key persistence, so each YARP route keeps its own leaf/chain/key.
        /// The route-scoped delegates accept the normalised route id; supply the key delegates so
        /// the renewal engine can reuse a route's private key across renewals.
        /// </summary>
        public IServiceCollection AddAcmeCertificatePersistence(
            Func<string, CertificateType, byte[], Task> persistWithRouteAsync,
            Func<string, CertificateType, Task<byte[]?>> retrieveWithRouteAsync,
            Func<string, System.Threading.CancellationToken, Task<string?>>? getRouteKeyAsync = null,
            Func<string, string, System.Threading.CancellationToken, Task>? persistRouteKeyAsync = null)
        {
            var persistAsync = (CertificateType persistenceType, byte[] data) =>
                persistWithRouteAsync(AcmeRouteConstants.DefaultRouteId, persistenceType, data);
            var retrieveAsync = (CertificateType persistenceType) =>
                retrieveWithRouteAsync(AcmeRouteConstants.DefaultRouteId, persistenceType);

            return services.AddAcmeCertificatePersistence(new CustomCertificatePersistenceStrategy(
                persistAsync,
                retrieveAsync,
                persistWithRouteAsync,
                retrieveWithRouteAsync,
                getRouteKeyAsync,
                persistRouteKeyAsync));
        }

        public IServiceCollection AddAcmeCertificatePersistence(
            ICertificatePersistenceStrategy certificatePersistenceStrategy)
        {
            return services.AddAcmeCertificatePersistence(_ => certificatePersistenceStrategy);
        }

        public IServiceCollection AddAcmeCertificatePersistence(
            Func<IServiceProvider, ICertificatePersistenceStrategy> certificatePersistenceStrategyFactory)
        {
            return services.AddAcmePersistenceService().AddSingleton(certificatePersistenceStrategyFactory);
        }

        public IServiceCollection AddAcmeFileCertificatePersistence(
            string relativeFilePath = "OpenCertServerAcmeCertificate")
        {
            return services.AddAcmeCertificatePersistence(new FileCertificatePersistenceStrategy(relativeFilePath));
        }

        /// <summary>
        /// Registers a certificate persistence strategy that stores the ACME site certificate in
        /// the operating-system X.509 certificate store.  The certificate is stored with its
        /// private key so it survives application restarts without a separate key file.
        /// </summary>
        /// <param name="subjectName">
        /// The subject (CN) or domain name used to identify the certificate inside the store,
        /// e.g. <c>"example.com"</c>.  Must match (or be a substring of) the certificate's
        /// Subject field.
        /// </param>
        /// <param name="storeName">
        /// The store to target.  Defaults to <see cref="StoreName.My"/> (the personal store).
        /// </param>
        /// <param name="storeLocation">
        /// The store location.  Defaults to <see cref="StoreLocation.CurrentUser"/>, which
        /// works without elevated privileges on Windows, macOS, and Linux.
        /// </param>
        /// <remarks>
        /// Account keys (ACME private keys) are <em>not</em> stored in the OS certificate store.
        /// Register an additional persistence strategy such as
        /// <see cref="AddAcmeFileCertificatePersistence"/> or
        /// <see cref="AddAcmeInMemoryCertificatesPersistence"/> to handle account key persistence.
        /// </remarks>
        public IServiceCollection AddAcmeCertificateStorePersistence(
            string subjectName,
            StoreName storeName = StoreName.My,
            StoreLocation storeLocation = StoreLocation.CurrentUser)
        {
            return services.AddAcmeCertificatePersistence(
                new CertificateStorePersistenceStrategy(subjectName, storeName, storeLocation));
        }

        public IServiceCollection AddAcmeChallengePersistence(
            Func<IEnumerable<ChallengeDto>, Task> persistAsync,
            Func<Task<IEnumerable<ChallengeDto>>> retrieveAsync,
            Func<IEnumerable<ChallengeDto>, Task> deleteAsync)
        {
            return services.AddAcmeChallengePersistence(
                new CustomChallengePersistenceStrategy(persistAsync, retrieveAsync, deleteAsync));
        }

        public IServiceCollection AddAcmeChallengePersistence(
            IChallengePersistenceStrategy certificatePersistenceStrategy)
        {
            return services.AddAcmeChallengePersistence(_ => certificatePersistenceStrategy);
        }

        public IServiceCollection AddAcmeChallengePersistence(
            Func<IServiceProvider, IChallengePersistenceStrategy> certificatePersistenceStrategyFactory)
        {
            return services.AddAcmePersistenceService().AddSingleton(certificatePersistenceStrategyFactory);
        }

        public IServiceCollection AddAcmeFileChallengePersistence(
            string relativeFilePath = "OpenCertServerAcmeChallenge")
        {
            return services.AddAcmeChallengePersistence(new FileChallengePersistenceStrategy(relativeFilePath));
        }

        public IServiceCollection AddAcmeMemoryChallengePersistence()
        {
            return services.AddAcmeChallengePersistence(new InMemoryChallengePersistenceStrategy());
        }

        public IServiceCollection AddAcmeInMemoryCertificatesPersistence()
        {
            return services.AddAcmeCertificatePersistence(new InMemoryCertificatePersistenceStrategy());
        }

        public IServiceCollection AddAcmeClient<
                TOptions,
                [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors)]
                TDnsChallengeProvider>(
            TOptions options)
            where TOptions : AcmeOptions
            where TDnsChallengeProvider : class, IDnsChallengeProvider
        {
            // A non-empty Domains array is no longer required here: in the per-route YARP path each
            // route's Match.Hosts supply the SANs, so Domains may be empty. The empty-Domains check is
            // deferred to AcmeRenewalService.StartAsync, where the route source can be inspected, so a
            // YARP-only deployment is not forced to provide redundant per-route domains.
            return services
                .AddSingleton<IDnsChallengeProvider, TDnsChallengeProvider>()
                .InnerAddAcmeClient(options);
        }

        public IServiceCollection AddAcmeClient<TOptions>(
            TOptions options,
            Func<IServiceProvider, IDnsChallengeProvider> dnsChallengeProviderFactory)
            where TOptions : AcmeOptions
        {
            // A non-empty Domains array is no longer required here: in the per-route YARP path each
            // route's Match.Hosts supply the SANs, so Domains may be empty. The empty-Domains check is
            // deferred to AcmeRenewalService.StartAsync, where the route source can be inspected, so a
            // YARP-only deployment is not forced to provide redundant per-route domains.
            return services
                .AddSingleton(dnsChallengeProviderFactory)
                .InnerAddAcmeClient(options);
        }

        public IServiceCollection AddAcmeClient<TOptions>(TOptions options)
            where TOptions : AcmeOptions
        {
            return services.AddAcmeClient<TOptions, NullDnsChallengeProvider>(options);
        }

        private IServiceCollection InnerAddAcmeClient<TOptions>(TOptions options)
            where TOptions : AcmeOptions
        {
            return services.AddTransient<IConfigureOptions<KestrelServerOptions>, KestrelOptionsSetup>()
                .AddAcmePersistenceService()
                .AddAcmeRouteConfigurationSource()
                .AddSingleton(options)
                .AddSingleton<AcmeOptions>(sp => sp.GetRequiredService<TOptions>())
                .AddSingleton<IValidateCertificates, CertificateValidator>()
                .AddSingleton<IProvideCertificates, CertificateProvider>()
                .AddSingleton<AcmeRouteScope>()
                .AddTransient<IHostedService>(sp => sp.GetRequiredService<IAcmeRenewalService>())
                .AddSingleton<IAcmeRenewalService, AcmeRenewalService>()
                .AddSingleton<IAcmeClientFactory, AcmeClientFactory>();
        }
    }

    extension(IApplicationBuilder app)
    {
        public IApplicationBuilder UseAcmeClient()
        {
            return app.UseMiddleware<AcmeChallengeApprovalMiddleware>();
        }
    }
}
