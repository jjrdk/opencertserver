namespace OpenCertServer.Acme.Server.Extensions
{
    using Abstractions.RequestServices;
    using Abstractions.Services;
    using Abstractions.Storage;
    using Abstractions.Workers;
    using BackgroundServices;
    using Configuration;
    using DnsClient;
    using Filters;
    using Microsoft.AspNetCore.Authorization.Infrastructure;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.Extensions.Configuration;
    using Microsoft.Extensions.DependencyInjection;
    using ModelBinding;
    using RequestServices;
    using Services;
    using Stores;
    using Workers;

    public static class ServiceCollectionExtensions
    {
        public static IServiceCollection AddAcmeServer(
            this IServiceCollection services,
            IConfiguration configuration,
            Func<IServiceProvider, HttpClient>? httpClient = null,
            AcmeServerOptions? acmeServerOptions = null,
            string sectionName = "AcmeServer")
        {
            services.AddControllers().AddApplicationPart(typeof(ServiceCollectionExtensions).Assembly);

            services.AddScoped<IAcmeRequestProvider, DefaultRequestProvider>();//.AddAuthorization();

            services.AddScoped<IRequestValidationService, DefaultRequestValidationService>();
            services.AddScoped<INonceService, DefaultNonceService>();
            services.AddScoped<IAccountService, DefaultAccountService>();
            services.AddScoped<IOrderService, DefaultOrderService>();

            services.AddScoped<IAuthorizationFactory, DefaultAuthorizationFactory>();

            services.AddScoped<IValidationWorker, ValidationWorker>();

            if (httpClient == null)
            {
                services.AddHttpClient<IHttp01ChallengeValidator, Http01ChallengeValidator>();
            }
            else
            {
                services.AddTransient(httpClient);
                services.AddTransient<IHttp01ChallengeValidator, Http01ChallengeValidator>();
            }

            services.AddScoped<ILookupClient, LookupClient>();
            services.AddScoped<IDns01ChallengeValidator, Dns01ChallengeValidator>();
            services.AddScoped<IChallengeValidatorFactory, DefaultChallengeValidatorFactory>();

            services.AddScoped<AddNextNonceFilter>();

            services.AddHostedService<HostedValidationService>();

            services.Configure<MvcOptions>(
                opt =>
                {
                    opt.Filters.Add(typeof(AcmeExceptionFilter));
                    opt.Filters.Add(typeof(ValidateAcmeRequestFilter));
                    opt.Filters.Add(typeof(AcmeIndexLinkFilter));

                    opt.ModelBinderProviders.Insert(0, new AcmeModelBindingProvider());
                });

            var acmeServerConfig = configuration.GetSection(sectionName);
            acmeServerOptions ??= new AcmeServerOptions();
            acmeServerConfig.Bind(acmeServerOptions);

            services.Configure<AcmeServerOptions>(acmeServerConfig);

            return services;
        }

        public static IServiceCollection AddAcmeFileStore(
            this IServiceCollection services,
            IConfiguration configuration,
            string sectionName = "AcmeFileStore")
        {
            services.AddScoped<INonceStore, NonceStore>();
            services.AddScoped<IAccountStore, AccountStore>();
            services.AddScoped<IOrderStore, OrderStore>();

            services.AddOptions<FileStoreOptions>()
                .Bind(configuration.GetSection(sectionName))
                .ValidateDataAnnotations();

            return services;
        }

        public static IServiceCollection AddAcmeInMemoryStore(
            this IServiceCollection services)
        {
            services.AddSingleton<INonceStore, InMemoryNonceStore>();
            services.AddSingleton<IAccountStore, InMemoryAccountStore>();
            services.AddSingleton<IOrderStore, InMemoryOrderStore>();
            
            return services;
        }
    }
}
