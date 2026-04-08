namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using CertesSlim.Extensions;
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
using System.Diagnostics.CodeAnalysis;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.AspNetClient.Certes;
using OpenCertServer.Acme.AspNetClient.Persistence;
using OpenCertServer.Acme.Server;
using OpenCertServer.Acme.Server.Configuration;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Ca.Server;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Est.Server;
using Reqnroll;
using Xunit;

[Binding]
public partial class CertificateServerFeatures
{
    private TestServer _server = null!;
    private IAcmeClient _acmeClient = null!;
    private bool _strictOcspHttpBinding;
    private TimeSpan _ocspFreshnessWindow = TimeSpan.FromHours(1);

    [UnconditionalSuppressMessage("Trimming", "IL2111",
        Justification = "The test host registers known concrete services in the regular test runtime and is not trimmed.")]
    [UnconditionalSuppressMessage("AOT", "IL3050",
        Justification = "These certserver tests do not target AOT publishing.")]
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

        void ConfigureApp(IApplicationBuilder app) =>
            app.UseCertificateForwarding().UseAcmeServer().UseEstServer().UseEndpoints(e =>
            {
                e.MapCertificateAuthorityServer();
            });

        [UnconditionalSuppressMessage("Trimming", "IL2067",
            Justification = "The certserver test host registers known concrete services only for the non-trimmed test runtime.")]
        [UnconditionalSuppressMessage("Trimming", "IL2111",
            Justification = "The certserver test host registers known concrete services only for the non-trimmed test runtime.")]
        [UnconditionalSuppressMessage("AOT", "IL3050",
            Justification = "These certserver tests do not target AOT publishing.")]
        void ConfigureServices(WebHostBuilderContext ctx, IServiceCollection services)
        {
            services
                .AddSingleton<IResponderId>(new ResponderIdByKey("test"u8.ToArray()))
                .AddInMemoryCertificateStore()
                .AddSelfSignedCertificateAuthority(new X500DistinguishedName("CN=reimers.io"), ocspUrls: ["test"], strictOcspHttpBinding: _strictOcspHttpBinding, ocspFreshnessWindow: _ocspFreshnessWindow)
                .AddEstServer<TestCsrAttributesLoader>()
                .AddSingleton<TestManualAuthorizationStrategy>()
                .Replace(ServiceDescriptor.Singleton<OpenCertServer.Est.Server.Handlers.IManualAuthorizationStrategy>(sp =>
                    sp.GetRequiredService<TestManualAuthorizationStrategy>()))
                .AddSingleton(sp => sp.GetRequiredService<ICertificateAuthority>().GetRootCertificates())
                .AddAcmeServer(ctx.Configuration, _ => _server.CreateClient(),
                    new AcmeServerOptions
                        { HostedWorkers = new BackgroundServiceOptions { EnableIssuanceService = false } })
                .AddSingleton<ICsrValidator, DefaultCsrValidator>()
                .AddAcmeInMemoryStore()
                .ConfigureOptions<ConfigureCertificateAuthenticationOptions>()
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
                            if (!c.Request.Headers.ContainsKey("Authorization"))
                            {
                                c.NoResult();
                                return Task.CompletedTask;
                            }

                            c.Principal =
                                new ClaimsPrincipal(
                                    new ClaimsIdentity([new Claim("role", "user")],
                                        JwtBearerDefaults.AuthenticationScheme));
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
                .AddCertificate();

            services.AddSingleton(sp => new DefaultIssuer(sp.GetRequiredService<ICertificateAuthority>()));
            services.AddSingleton(sp => new TestAcmeIssuer(sp.GetRequiredService<DefaultIssuer>()));
            services.AddSingleton<TestAcmeChallengeValidationState>();
            services.AddSingleton<IValidateHttp01Challenges, TestAcmeHttp01ChallengeValidator>();
            services.AddSingleton<IValidateDns01Challenges, TestAcmeDns01ChallengeValidator>();
            services.Replace(ServiceDescriptor.Singleton<IIssueCertificates>(sp => sp.GetRequiredService<TestAcmeIssuer>()));
        }
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
                Profile = keyAlgorithm.StartsWith("RS") ? "rsa" : "ecdsa",
                Email = "test@test.com",
                Domains = ["localhost"],
                KeyAlgorithm = keyAlgorithm,
                CertificateSigningRequest = new CsrInfo { CommonName = "test", CountryName = "DK" },
                AccountPassword = "test"
            },
            _server.CreateClient(),
            NullLoggerFactory.Instance);

        _acmeClient = await factory.GetClient();
    }

    [When(@"the client requests a certificate")]
    public async Task WhenTheClientRequestsACertificate()
    {
        var placedOrder = await _acmeClient.PlaceOrder( ["localhost"]);

        Assert.NotNull(placedOrder);

        _scenarioContext["placedOrder"] = placedOrder;
    }

    [When("I query the certificate inventory")]
    public async Task WhenIQueryTheCertificateInventory()
    {
        var client = _server.CreateClient();
        var response = await client.GetAsync("/ca/inventory");
        response.EnsureSuccessStatusCode();
        var inventory = await JsonSerializer.DeserializeAsync<CertificateItemInfo[]>(
            await response.Content.ReadAsStreamAsync(), CaServerSerializerContext.Default.CertificateItemInfoArray);

        Assert.NotNull(inventory);

        _scenarioContext["inventory"] = inventory;
    }

    [Then(@"the client receives a certificate")]
    public async Task ThenTheClientReceivesACertificate()
    {
        var cert = await _acmeClient.FinalizeOrder(_scenarioContext["placedOrder"]! as PlacedOrder
         ?? throw new InvalidOperationException());

        Assert.NotNull(cert);
    }

    [Then("the certificate should be included in the inventory")]
    public void ThenTheCertificateShouldBeIncludedInTheInventory()
    {
        var inventory = _scenarioContext["inventory"] as CertificateItemInfo[]
         ?? throw new InvalidOperationException();

        Assert.Single(inventory);
    }

    [BeforeScenario("@strict-ocsp")]
    public void EnableStrictOcspHttpBinding()
    {
        _strictOcspHttpBinding = true;
    }

    [BeforeScenario("@custom-ocsp-freshness")]
    public void SetCustomOcspFreshnessWindow()
    {
        _ocspFreshnessWindow = TimeSpan.FromHours(2);
    }
}
