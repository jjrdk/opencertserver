
using System.Runtime.CompilerServices;
[assembly: InternalsVisibleTo("opencertserver.acme.aspnetclient.tests")]
[assembly: InternalsVisibleTo("opencertserver.certserver.tests")]

// ReSharper disable once CheckNamespace
namespace OpenCertServer.AspNet.EncryptWeMust;

using System.Collections.Generic;
using OpenCertServer.Acme.AspNetClient;
using OpenCertServer.Acme.AspNetClient.Certes;
using OpenCertServer.Acme.AspNetClient.Certificates;
using OpenCertServer.Acme.AspNetClient.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;

public static class RegistrationExtensions
{
    private static IServiceCollection AddAcmePersistenceService(this IServiceCollection services)
    {
        return services.Any(x => x.ServiceType == typeof(IPersistenceService))
            ? services
            : services.AddSingleton<IPersistenceService, PersistenceService>();
    }

    public static IServiceCollection AddAcmeRenewalLifecycleHook<TCertificateRenewalLifecycleHook>(
        this IServiceCollection services)
        where TCertificateRenewalLifecycleHook : class, ICertificateRenewalLifecycleHook
    {
        return services.AddAcmePersistenceService()
            .AddSingleton<ICertificateRenewalLifecycleHook, TCertificateRenewalLifecycleHook>();
    }

    public static IServiceCollection AddAcmeCertificatePersistence(
        this IServiceCollection services,
        Func<CertificateType, byte[], Task> persistAsync,
        Func<CertificateType, Task<byte[]?>> retrieveAsync)
    {
        return AddAcmeCertificatePersistence(
            services,
            new CustomCertificatePersistenceStrategy(persistAsync, retrieveAsync));
    }

    public static IServiceCollection AddAcmeCertificatePersistence(
        this IServiceCollection services,
        ICertificatePersistenceStrategy certificatePersistenceStrategy)
    {
        return AddAcmeCertificatePersistence(services, _ => certificatePersistenceStrategy);
    }

    public static IServiceCollection AddAcmeCertificatePersistence(
        this IServiceCollection services,
        Func<IServiceProvider, ICertificatePersistenceStrategy> certificatePersistenceStrategyFactory)
    {
        return services.AddAcmePersistenceService().AddSingleton(certificatePersistenceStrategyFactory);
    }

    public static IServiceCollection AddAcmeFileCertificatePersistence(
        this IServiceCollection services,
        string relativeFilePath = "OpenCertServerAcmeCertificate")
    {
        return AddAcmeCertificatePersistence(
            services,
            new FileCertificatePersistenceStrategy(relativeFilePath));
    }

    public static IServiceCollection AddAcmeChallengePersistence(
        this IServiceCollection services,
        Func<IEnumerable<ChallengeDto>, Task> persistAsync,
        Func<Task<IEnumerable<ChallengeDto>>> retrieveAsync,
        Func<IEnumerable<ChallengeDto>, Task> deleteAsync)
    {
        return AddAcmeChallengePersistence(
            services,
            new CustomChallengePersistenceStrategy(persistAsync, retrieveAsync, deleteAsync));
    }

    public static IServiceCollection AddAcmeChallengePersistence(
        this IServiceCollection services,
        IChallengePersistenceStrategy certificatePersistenceStrategy)
    {
        return AddAcmeChallengePersistence(services, _ => certificatePersistenceStrategy);
    }

    public static IServiceCollection AddAcmeChallengePersistence(
        this IServiceCollection services,
        Func<IServiceProvider, IChallengePersistenceStrategy> certificatePersistenceStrategyFactory)
    {
        return services.AddAcmePersistenceService().AddSingleton(certificatePersistenceStrategyFactory);
    }

    public static IServiceCollection AddAcmeFileChallengePersistence(
        this IServiceCollection services,
        string relativeFilePath = "OpenCertServerAcmeChallenge")
    {
        return AddAcmeChallengePersistence(services, new FileChallengePersistenceStrategy(relativeFilePath));
    }

    public static IServiceCollection AddAcmeMemoryChallengePersistence(this IServiceCollection services)
    {
        return AddAcmeChallengePersistence(services, new InMemoryChallengePersistenceStrategy());
    }

    public static IServiceCollection AddAcmeInMemoryCertificatesPersistence(this IServiceCollection services)
    {
        return AddAcmeCertificatePersistence(services, new InMemoryCertificatePersistenceStrategy());
    }

    public static IServiceCollection AddAcmeClient<TOptions>(this IServiceCollection services, TOptions options)
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

    public static IApplicationBuilder UseAcmeClient(this IApplicationBuilder app)
    {
        return app.UseMiddleware<AcmeChallengeApprovalMiddleware>();
    }
}