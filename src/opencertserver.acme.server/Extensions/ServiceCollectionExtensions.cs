namespace OpenCertServer.Acme.Server.Extensions;

using Abstractions.RequestServices;
using Abstractions.Services;
using Abstractions.Storage;
using Abstractions.Workers;
using BackgroundServices;
using Configuration;
using DnsClientX;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using RequestServices;
using Services;
using Stores;
using Workers;

public static class ServiceCollectionExtensions
{
    extension(IServiceCollection services)
    {
        public IServiceCollection AddAcmeServer(
            IConfiguration configuration,
            Func<IServiceProvider, HttpClient>? httpClient = null,
            AcmeServerOptions? acmeServerOptions = null,
            string sectionName = "AcmeServer")
        {
            var acmeServerConfig = configuration.GetSection(sectionName);
            acmeServerOptions ??= new AcmeServerOptions();
            acmeServerConfig.Bind(acmeServerOptions);

            services.AddScoped<IRequestValidationService, DefaultRequestValidationService>();
            services.AddScoped<INonceService, DefaultNonceService>();
            services.AddScoped<IAccountService, DefaultAccountService>();
            services.AddScoped<IOrderService, DefaultOrderService>();
            services.AddScoped<IRevocationService, DefaultRevocationService>();
            services.AddScoped<IExternalAccountBindingService, DefaultExternalAccountBindingService>();

            services.AddScoped<IAuthorizationFactory, DefaultAuthorizationFactory>();
            services.AddScoped<IAllowedIdentifiersPolicy, DefaultAllowedIdentifiersPolicy>();

            services.AddScoped<IValidationWorker, ValidationWorker>();

            if (httpClient == null)
            {
                services.AddHttpClient<IValidateHttp01Challenges, ValidateHttp01Challenges>()
                    .ConfigurePrimaryHttpMessageHandler(SsrfBlockingSocketsHandler.Create)
                    .ConfigureHttpClient(client => client.Timeout = acmeServerOptions.UrlRetrievalTimeout);
            }
            else
            {
                services.AddTransient<IValidateHttp01Challenges>(sp =>
                    new ValidateHttp01Challenges(
                        ConfigureUrlRetrievalClient(httpClient(sp), acmeServerOptions.UrlRetrievalTimeout),
                        sp.GetRequiredService<ICaaValidator>()));
            }

            static HttpClient ConfigureUrlRetrievalClient(HttpClient client, TimeSpan timeout)
            {
                client.Timeout = timeout;
                return client;
            }

            services.AddSingleton<ClientX>(sp =>
            {
                var opts = sp.GetRequiredService<IOptions<AcmeServerOptions>>();
                return new ClientX(opts.Value.DnsEndpoint);
            });
            services.AddScoped<IDnsResolver, DnsClientXResolver>();
            services.AddScoped<ICaaValidator, CaaValidator>();
            services.AddScoped<IValidateDns01Challenges, ValidateDns01Challenges>();
            services.AddSingleton<IAttestationTrustProvider>(
                new StaticAttestationTrustProvider([]));
            services.AddScoped<IValidateDeviceAttestChallenges, DeviceAttestChallengeValidator>();
            services.AddScoped<IChallengeValidatorFactory, DefaultChallengeValidatorFactory>();

            services.AddHostedService<HostedValidationService>();

            services.Configure<AcmeServerOptions>(acmeServerConfig);

            return services;
        }

        public IServiceCollection AddAcmeFileStore(
            IConfiguration configuration,
            string sectionName = "AcmeFileStore")
        {
            services.AddScoped<INonceStore, NonceStore>();
            services.AddScoped<IStoreAccounts, AccountStore>();
            services.AddScoped<IStoreOrders, OrderStore>();
            services.AddScoped<IStoreExternalAccountKeys, ExternalAccountKeyStore>();

            services.AddOptions<FileStoreOptions>()
                .Bind(configuration.GetSection(sectionName));

            return services;
        }

        public IServiceCollection AddAcmeInMemoryStore()
        {
            services.AddSingleton<INonceStore, InMemoryNonceStore>();
            services.AddSingleton<IStoreAccounts, InMemoryAccountStore>();
            services.AddSingleton<IStoreOrders, InMemoryOrderStore>();
            services.AddSingleton<IStoreExternalAccountKeys, InMemoryExternalAccountKeyStore>();

            return services;
        }
    }
}
