using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using OpenCertServer.Acme.AspNetClient.Certes;
using OpenCertServer.Acme.AspNetClient.Certificates;
using OpenCertServer.Acme.AspNetClient.Persistence;

[assembly: InternalsVisibleTo("opencertserver.acme.aspnetclient.tests")]
[assembly: InternalsVisibleTo("opencertserver.certserver.tests")]

namespace OpenCertServer.Acme.AspNetClient;

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
            return services.AddAcmeCertificatePersistence(new CustomCertificatePersistenceStrategy(persistAsync, retrieveAsync));
        }

        public IServiceCollection AddAcmeCertificatePersistence(ICertificatePersistenceStrategy certificatePersistenceStrategy)
        {
            return services.AddAcmeCertificatePersistence(_ => certificatePersistenceStrategy);
        }

        public IServiceCollection AddAcmeCertificatePersistence(Func<IServiceProvider, ICertificatePersistenceStrategy> certificatePersistenceStrategyFactory)
        {
            return services.AddAcmePersistenceService().AddSingleton(certificatePersistenceStrategyFactory);
        }

        public IServiceCollection AddAcmeFileCertificatePersistence(string relativeFilePath = "OpenCertServerAcmeCertificate")
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
            return services.AddAcmeChallengePersistence(new CustomChallengePersistenceStrategy(persistAsync, retrieveAsync, deleteAsync));
        }

        public IServiceCollection AddAcmeChallengePersistence(IChallengePersistenceStrategy certificatePersistenceStrategy)
        {
            return services.AddAcmeChallengePersistence(_ => certificatePersistenceStrategy);
        }

        public IServiceCollection AddAcmeChallengePersistence(Func<IServiceProvider, IChallengePersistenceStrategy> certificatePersistenceStrategyFactory)
        {
            return services.AddAcmePersistenceService().AddSingleton(certificatePersistenceStrategyFactory);
        }

        public IServiceCollection AddAcmeFileChallengePersistence(string relativeFilePath = "OpenCertServerAcmeChallenge")
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

        public IServiceCollection AddAcmeClient<TOptions>(TOptions options)
            where TOptions : AcmeOptions
        {
            if (options.Domains?.Distinct().Any() != true)
            {
                throw new ArgumentException("Domains configuration invalid");
            }

            return services.AddTransient<IConfigureOptions<KestrelServerOptions>, KestrelOptionsSetup>()
                .AddAcmePersistenceService()
                .AddSingleton(options)
                .AddSingleton<AcmeOptions>(sp => sp.GetRequiredService<TOptions>())
                .AddSingleton<IValidateCertificates, CertificateValidator>()
                .AddSingleton<IProvideCertificates, CertificateProvider>()
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
