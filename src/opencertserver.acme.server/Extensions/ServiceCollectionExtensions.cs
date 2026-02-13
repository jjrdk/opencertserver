namespace OpenCertServer.Acme.Server.Extensions;

using Abstractions.RequestServices;
using Abstractions.Services;
using Abstractions.Storage;
using Abstractions.Workers;
using BackgroundServices;
using Configuration;
using DnsClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
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
            services.AddScoped<IRequestValidationService, DefaultRequestValidationService>();
            services.AddScoped<INonceService, DefaultNonceService>();
            services.AddScoped<IAccountService, DefaultAccountService>();
            services.AddScoped<IOrderService, DefaultOrderService>();

            services.AddScoped<IAuthorizationFactory, DefaultAuthorizationFactory>();

            services.AddScoped<IValidationWorker, ValidationWorker>();

            if (httpClient == null)
            {
                services.AddHttpClient<IValidateHttp01Challenges, ValidateHttp01Challenges>();
            }
            else
            {
                services.AddTransient(httpClient);
                services.AddTransient<IValidateHttp01Challenges, ValidateHttp01Challenges>();
            }

            services.AddScoped<ILookupClient, LookupClient>();
            services.AddScoped<IValidateDns01Challenges, ValidateDns01Challenges>();
            services.AddScoped<IChallengeValidatorFactory, DefaultChallengeValidatorFactory>();

//            services.AddScoped<AddNextNonceFilter>();

            services.AddHostedService<HostedValidationService>();
//
//            services.Configure<MvcOptions>(
//                opt =>
//                {
//                    opt.Filters.Add(typeof(AcmeExceptionFilter));
//                    opt.Filters.Add(typeof(ValidateAcmeRequestFilter));
//                    opt.Filters.Add(typeof(AcmeIndexLinkFilter));
//
//                    opt.ModelBinderProviders.Insert(0, new AcmeModelBindingProvider());
//                });

            var acmeServerConfig = configuration.GetSection(sectionName);
            acmeServerOptions ??= new AcmeServerOptions();
            acmeServerConfig.Bind(acmeServerOptions);

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

            services.AddOptions<FileStoreOptions>()
                .Bind(configuration.GetSection(sectionName));

            return services;
        }

        public IServiceCollection AddAcmeInMemoryStore()
        {
            services.AddSingleton<INonceStore, InMemoryNonceStore>();
            services.AddSingleton<IStoreAccounts, InMemoryAccountStore>();
            services.AddSingleton<IStoreOrders, InMemoryOrderStore>();

            return services;
        }
    }
}
