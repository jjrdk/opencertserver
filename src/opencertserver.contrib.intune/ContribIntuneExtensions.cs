namespace OpenCertServer.Contrib.Intune;

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenCertServer.Scep.Server;

public static class ContribIntuneExtensions
{
    /// <summary>The policy name the sync endpoint requires; configure it with <c>AddAuthorization</c>.</summary>
    public const string SyncPolicyName = "scep_intune_sync";

    extension(IServiceCollection services)
    {
        /// <summary>
        /// Registers the Intune challenge validator and the revocation sync. Call it
        /// <b>instead of</b> passing a validator to <c>AddScepServer</c>: the SCEP server
        /// then takes the validator from the container.
        /// </summary>
        public IServiceCollection AddIntune(IntuneOptions options, Action<IHttpClientBuilder>? configureHttp = null)
        {
            services.AddSingleton(options);
            var http = services.AddHttpClient<IIntuneClient, IntuneClient>();
            configureHttp?.Invoke(http);
            services.TryAddSingleton(TimeProvider.System);
            // Replace, not TryAdd: AddScepServer(options) registers the "not configured"
            // validator with TryAdd, so this works in either order.
            services.RemoveAll<IScepChallengeValidator>();
            services.AddSingleton<IScepChallengeValidator, IntuneChallengeValidator>();
            services.AddSingleton<IntuneRevocationSync>();
            return services;
        }

        /// <summary>
        /// Reads <see cref="IntuneOptions"/> from <c>Scep:Intune</c> - value by value, not
        /// through the binder, so the package stays trimmable.
        /// </summary>
        public IServiceCollection AddIntune(IConfiguration configuration)
        {
            var section = configuration.GetSection(IntuneOptions.SectionName);
            if (!section.Exists())
            {
                throw new InvalidOperationException($"{IntuneOptions.SectionName} is not configured.");
            }

            var defaults = new IntuneOptions { TenantId = "", ClientId = "" };
            var options = new IntuneOptions
            {
                TenantId = section[nameof(IntuneOptions.TenantId)]
                           ?? throw new InvalidOperationException($"{IntuneOptions.SectionName}:TenantId is missing."),
                ClientId = section[nameof(IntuneOptions.ClientId)]
                           ?? throw new InvalidOperationException($"{IntuneOptions.SectionName}:ClientId is missing."),
                ClientCertificateFile = section[nameof(IntuneOptions.ClientCertificateFile)],
                ClientCertificateKeyFile = section[nameof(IntuneOptions.ClientCertificateKeyFile)],
                ClientSecret = section[nameof(IntuneOptions.ClientSecret)],
                ClientSecretFile = section[nameof(IntuneOptions.ClientSecretFile)],
                CallerInfo = section[nameof(IntuneOptions.CallerInfo)] ?? defaults.CallerInfo,
                LoginBase = Address(section, nameof(IntuneOptions.LoginBase)) ?? defaults.LoginBase,
                GraphBase = Address(section, nameof(IntuneOptions.GraphBase)) ?? defaults.GraphBase,
                IntuneResource = Address(section, nameof(IntuneOptions.IntuneResource)) ?? defaults.IntuneResource,
                ValidationEndpoint = Address(section, nameof(IntuneOptions.ValidationEndpoint)),
                Timeout = TimeSpan.TryParse(section[nameof(IntuneOptions.Timeout)], out var timeout) ? timeout : defaults.Timeout,
                MaxRevocationsPerSync = int.TryParse(section[nameof(IntuneOptions.MaxRevocationsPerSync)], out var max)
                    ? max
                    : defaults.MaxRevocationsPerSync
            };
            return services.AddIntune(options);
        }
    }

    private static Uri? Address(IConfiguration section, string key) =>
        section[key] is { Length: > 0 } value ? new Uri(value, UriKind.Absolute) : null;

    extension(IEndpointRouteBuilder endpoints)
    {
        /// <summary>
        /// <c>POST {path}?dryRun=true|false</c> runs the revocation sync and returns the
        /// report; 409 while another run is in progress. Requires the policy
        /// <see cref="SyncPolicyName"/> - only the caller configured for it may revoke.
        /// </summary>
        public IEndpointRouteBuilder MapIntuneSync(string path = "/scep/intune/sync")
        {
            endpoints.MapPost(path, SyncHandler.Handle).RequireAuthorization(SyncPolicyName);
            return endpoints;
        }
    }
}
