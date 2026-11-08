using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace OpenCertServer.Acme.Server.Extensions;

using Abstractions.RequestServices;
using Abstractions.Services;
using Abstractions.Storage;
using Abstractions.Workers;
using BackgroundServices;
using Configuration;
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
                {
                    var dnsResolver = sp.GetRequiredService<IDnsResolver>();
                    return new ValidateHttp01Challenges(
                        ConfigureUrlRetrievalClient(httpClient(sp),
                            acmeServerOptions.UrlRetrievalTimeout),
                        new CaaValidator(
                            NullLogger<CaaValidator>.Instance,
                            dnsResolver,
                            sp.GetRequiredService<IOptions<AcmeServerOptions>>()),
                        dnsResolver);
                });
            }

            static HttpClient ConfigureUrlRetrievalClient(HttpClient client, TimeSpan timeout)
            {
                client.Timeout = timeout;
                return client;
            }

            static void Apply(AcmeServerOptions source, AcmeServerOptions target)
            {
                target.HostedWorkers = source.HostedWorkers;
                target.WebsiteUrl = source.WebsiteUrl;
                target.UrlRetrievalTimeout = source.UrlRetrievalTimeout;
                target.ExternalAccountRequired = source.ExternalAccountRequired;
                target.TOS = source.TOS;
                target.CAAIdentities = source.CAAIdentities;
                target.DohServers = source.DohServers;
                target.DnsQueryTimeout = source.DnsQueryTimeout;
                target.DnsEndpoint = source.DnsEndpoint;
                target.DisableCaaChecks = source.DisableCaaChecks;
            }

            services.AddSingleton<IDnsResolver>(sp =>
            {
                var opts = sp.GetRequiredService<IOptions<AcmeServerOptions>>().Value;
                var timeoutMilliseconds = (int)Math.Clamp(
                    opts.DnsQueryTimeout.TotalMilliseconds,
                    1,
                    int.MaxValue);
                var perspectives = DnsPerspectiveFactory.Create(opts, timeoutMilliseconds);
                return new MultiPerspectiveDnsResolver(
                    perspectives,
                    sp.GetRequiredService<ILogger<MultiPerspectiveDnsResolver>>());
            });
            services.AddScoped<ICaaValidator, CaaValidator>();
            services.AddScoped<IValidateDns01Challenges, ValidateDns01Challenges>();
            services.AddSingleton<IAttestationTrustProvider>(
                new StaticAttestationTrustProvider([]));
            services.AddScoped<IValidateDeviceAttestChallenges, DeviceAttestChallengeValidator>();
            services.AddScoped<IChallengeValidatorFactory, DefaultChallengeValidatorFactory>();

            services.AddHostedService<HostedValidationService>();

            // The supplied instance has already had the configuration section bound into it,
            // so copy its values into the options pipeline instead of binding a separate
            // instance. This keeps programmatic settings (for example DohServers and
            // DnsQueryTimeout) visible to consumers of IOptions<AcmeServerOptions>.
            services.Configure<AcmeServerOptions>(options => Apply(acmeServerOptions, options));

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
