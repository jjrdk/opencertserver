using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using Certes;
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
using OpenCertServer.Est.Server;
using TechTalk.SpecFlow;
using Xunit;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

[Binding]
public partial class CertificateServerFeatures
{
    private TestServer _server = null!;
    private IAcmeClient _client = null!;
    private PlacedOrder _placedOrder = null!;

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
            app.UseAcmeServer().UseEstServer().UseRouting().UseEndpoints(e => e.MapControllers());

        [UnconditionalSuppressMessage("Trimming",
            "IL2026:Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code",
            Justification = "<Pending>")]
        [UnconditionalSuppressMessage("AOT",
            "IL3050:Calling members annotated with 'RequiresDynamicCodeAttribute' may break functionality when AOT compiling.",
            Justification = "<Pending>")]
        void ConfigureServices(WebHostBuilderContext ctx, IServiceCollection services) =>
            services.AddEstServer(new X500DistinguishedName("CN=reimers.io"))
                .AddAcmeServer(ctx.Configuration, _ => _server.CreateClient(),
                    new AcmeServerOptions
                        { HostedWorkers = new BackgroundServiceOptions { EnableIssuanceService = false } })
                .AddSingleton<ICsrValidator, DefaultCsrValidator>()
                .AddSingleton<ICertificateIssuer, DefaultIssuer>()
                .Replace(new ServiceDescriptor(typeof(IValidateHttp01Challenges), typeof(PassAllChallenges),
                    ServiceLifetime.Transient))
                .AddAcmeInMemoryStore()
                .AddCertificateForwarding(o =>
                {
                    o.HeaderConverter = x => X509CertificateLoader.LoadCertificate(Convert.FromBase64String(x));
                })
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
                .AddCertificate();
    }

    [Given(@"an ACME client for (.+)")]
    public async Task GivenAnAcmeClientForKeyAlgorithm(string algo)
    {
        var keyAlgorithm = Enum.Parse<KeyAlgorithm>(algo, true);
        var factory = new AcmeClientFactory(
            new PersistenceService(
                new List<ICertificatePersistenceStrategy> { new InMemoryCertificatePersistenceStrategy() },
                new List<IChallengePersistenceStrategy> { new InMemoryChallengePersistenceStrategy() },
                NullLogger<IPersistenceService>.Instance),
            new TestAcmeOptions
            {
                Email = "test@test.com",
                Domains = ["localhost"],
                KeyAlgorithm = keyAlgorithm,
                CertificateSigningRequest = new CsrInfo { CommonName = "test", CountryName = "DK" }
            },
            _server.CreateClient(),
            NullLoggerFactory.Instance);

        _client = await factory.GetClient();
    }

    [When(@"the client requests a certificate")]
    public async Task WhenTheClientRequestsACertificate()
    {
        _placedOrder = await _client.PlaceOrder("localhost");

        Assert.NotNull(_placedOrder);
    }

    [Then(@"the client receives a certificate")]
    public async Task ThenTheClientReceivesACertificate()
    {
        var cert = await _client.FinalizeOrder(_placedOrder);

        Assert.NotNull(cert);
    }
}
