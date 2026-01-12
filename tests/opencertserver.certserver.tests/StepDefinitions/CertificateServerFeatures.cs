using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using CertesSlim.Extensions;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.AspNetClient.Certes;
using OpenCertServer.Acme.AspNetClient.Persistence;
using OpenCertServer.Acme.Server.Configuration;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Acme.Server.Middleware;
using OpenCertServer.Acme.Server.Services;
using opencertserver.ca.server;
using OpenCertServer.Est.Server;
using TechTalk.SpecFlow;
using Xunit;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

[Binding]
public partial class CertificateServerFeatures
{
    private TestServer _server = null!;
    private IAcmeClient _acmeClient = null!;

    [Given(@"a certificate server")]
    public void GivenACertificateServer()
    {
        var host = new HostBuilder().ConfigureWebHost(builder =>
        {
            builder
                .UseTestServer()
                .UseUrls("http://localhost")
                .ConfigureAppConfiguration(c => c.AddEnvironmentVariables())
                .ConfigureServices(ConfigureServices)
                .Configure(ConfigureApp);
        }).Build();
        host.Start();
        _server = host.GetTestServer();
        return;

        [UnconditionalSuppressMessage("Trimming",
            "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code",
            Justification = "<Pending>")]
        void ConfigureApp(IApplicationBuilder app) =>
            app.UseAcmeServer().UseEstServer().UseEndpoints(e =>
            {
                e.MapControllers();
                e.MapCertificateAuthorityServer();
            });

        [UnconditionalSuppressMessage("Trimming",
            "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code",
            Justification = "<Pending>")]
        [UnconditionalSuppressMessage("AOT",
            "IL3050:Calling members annotated with 'RequiresDynamicCodeAttribute' may break functionality when AOT compiling.",
            Justification = "<Pending>")]
        void ConfigureServices(WebHostBuilderContext ctx, IServiceCollection services) =>
#pragma warning disable IL2066
            services.AddInMemoryEstServer(new X500DistinguishedName("CN=reimers.io"), ocspUrls: ["test"])
                .AddAcmeServer(ctx.Configuration, _ => _server.CreateClient(),
                    new AcmeServerOptions
                        { HostedWorkers = new BackgroundServiceOptions { EnableIssuanceService = false } })
                .AddSingleton<ICsrValidator, DefaultCsrValidator>()
#pragma warning restore IL2066
                .AddSingleton<IIssueCertificates, DefaultIssuer>()
                .Replace(new ServiceDescriptor(typeof(IValidateHttp01Challenges), typeof(PassAllChallenges),
                    ServiceLifetime.Transient))
                .AddAcmeInMemoryStore()
                .AddRouting()
                .AddAuthorization()
                .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, o =>
                {
                    o.SaveToken = true;
                    o.Events = new JwtBearerEvents
                    {
                        OnAuthenticationFailed = c =>
                        {
                            c.Principal =
                                new ClaimsPrincipal(
                                    new ClaimsIdentity([new Claim("role", "user")],
                                        "Bearer"));
                            c.Properties = new OAuthChallengeProperties
                            {
                                AllowRefresh = false, RedirectUri = "http://localhost",
                                ExpiresUtc = DateTimeOffset.UtcNow.AddDays(1), IssuedUtc = DateTimeOffset.UtcNow,
                                IsPersistent = false, Scope = ["openid"]
                            };
                            c.Success();
                            return Task.CompletedTask;
                        }
                    };
                })
                .AddCertificate(options =>
                {
                    var knownPrefixes = ImmutableDictionary.CreateRange([
                        KeyValuePair.Create("CN", ClaimTypes.Name),
                        KeyValuePair.Create("E", ClaimTypes.Email),
                        KeyValuePair.Create("OU", ClaimTypes.System),
                        KeyValuePair.Create("O", "org"),
                        KeyValuePair.Create("L", ClaimTypes.Locality),
                        KeyValuePair.Create("SN", ClaimTypes.Surname),
                        KeyValuePair.Create("GN", ClaimTypes.GivenName),
                        KeyValuePair.Create("C", ClaimTypes.Country)
                    ]);

                    options.AllowedCertificateTypes = CertificateTypes.All;
                    options.ChainTrustValidationMode = X509ChainTrustMode.CustomRootTrust;
                    options.Events = new CertificateAuthenticationEvents
                    {
                        OnCertificateValidated = context =>
                        {
                            var claims = context.ClientCertificate.SubjectName.Name
                                .Split(",", StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                                .Select(x => (x[..x.IndexOf('=')], x[(x.IndexOf('=') + 1)..]))
                                .Where(x => knownPrefixes.ContainsKey(x.Item1))
                                .Select(x => new Claim(knownPrefixes[x.Item1], x.Item2));
                            context.Principal = new ClaimsPrincipal(
                                new ClaimsIdentity(
                                    claims,
                                    CertificateAuthenticationDefaults.AuthenticationScheme));
                            context.Success();
                            return Task.CompletedTask;
                        }
                    };
                });
    }

    [Given(@"an ACME client for (.+)")]
    public async Task GivenAnAcmeClientFor(string keyAlgorithm)
    {
        var factory = new AcmeClientFactory(
            new PersistenceService(
                new List<ICertificatePersistenceStrategy> { new InMemoryCertificatePersistenceStrategy() },
                new List<IChallengePersistenceStrategy> { new InMemoryChallengePersistenceStrategy() },
                NullLogger<PersistenceService>.Instance),
            new TestAcmeOptions
            {
                Email = "test@test.com",
                Domains = ["localhost"],
                KeyAlgorithm = keyAlgorithm,
                CertificateSigningRequest = new CsrInfo { CommonName = "test", CountryName = "DK" }
            },
            _server.CreateClient(),
            NullLoggerFactory.Instance);

        _acmeClient = await factory.GetClient();
    }

    [When(@"the client requests a certificate")]
    public async Task WhenTheClientRequestsACertificate()
    {
        var placedOrder = await _acmeClient.PlaceOrder("localhost");

        Assert.NotNull(placedOrder);

        _scenarioContext["placedOrder"] = placedOrder;
    }

    [Then(@"the client receives a certificate")]
    public async Task ThenTheClientReceivesACertificate()
    {
        var cert = await _acmeClient.FinalizeOrder(_scenarioContext["placedOrder"]! as PlacedOrder
         ?? throw new InvalidOperationException());

        Assert.NotNull(cert);
    }
}
