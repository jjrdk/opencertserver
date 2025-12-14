using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
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
            return AddAcmeCertificatePersistence(
                services,
                new CustomCertificatePersistenceStrategy(persistAsync, retrieveAsync));
        }

        public IServiceCollection AddAcmeCertificatePersistence(ICertificatePersistenceStrategy certificatePersistenceStrategy)
        {
            return AddAcmeCertificatePersistence(services, _ => certificatePersistenceStrategy);
        }

        public IServiceCollection AddAcmeCertificatePersistence(Func<IServiceProvider, ICertificatePersistenceStrategy> certificatePersistenceStrategyFactory)
        {
            return services.AddAcmePersistenceService().AddSingleton(certificatePersistenceStrategyFactory);
        }

        public IServiceCollection AddAcmeFileCertificatePersistence(string relativeFilePath = "OpenCertServerAcmeCertificate")
        {
            return AddAcmeCertificatePersistence(
                services,
                new FileCertificatePersistenceStrategy(relativeFilePath));
        }

        public IServiceCollection AddAcmeChallengePersistence(
            Func<IEnumerable<ChallengeDto>, Task> persistAsync,
            Func<Task<IEnumerable<ChallengeDto>>> retrieveAsync,
            Func<IEnumerable<ChallengeDto>, Task> deleteAsync)
        {
            return AddAcmeChallengePersistence(
                services,
                new CustomChallengePersistenceStrategy(persistAsync, retrieveAsync, deleteAsync));
        }

        public IServiceCollection AddAcmeChallengePersistence(IChallengePersistenceStrategy certificatePersistenceStrategy)
        {
            return AddAcmeChallengePersistence(services, _ => certificatePersistenceStrategy);
        }

        public IServiceCollection AddAcmeChallengePersistence(Func<IServiceProvider, IChallengePersistenceStrategy> certificatePersistenceStrategyFactory)
        {
            return services.AddAcmePersistenceService().AddSingleton(certificatePersistenceStrategyFactory);
        }

        public IServiceCollection AddAcmeFileChallengePersistence(string relativeFilePath = "OpenCertServerAcmeChallenge")
        {
            return AddAcmeChallengePersistence(services, new FileChallengePersistenceStrategy(relativeFilePath));
        }

        public IServiceCollection AddAcmeMemoryChallengePersistence()
        {
            return AddAcmeChallengePersistence(services, new InMemoryChallengePersistenceStrategy());
        }

        public IServiceCollection AddAcmeInMemoryCertificatesPersistence()
        {
            return AddAcmeCertificatePersistence(services, new InMemoryCertificatePersistenceStrategy());
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

    public static IApplicationBuilder UseAcmeClient(this IApplicationBuilder app)
    {
        return app.UseMiddleware<AcmeChallengeApprovalMiddleware>();
    }
}
