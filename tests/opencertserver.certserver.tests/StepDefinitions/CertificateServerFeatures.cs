using System.Security.Cryptography.X509Certificates;
using Certes;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.AspNetClient.Certes;
using OpenCertServer.Acme.AspNetClient.Persistence;
using OpenCertServer.Acme.Server.Configuration;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Acme.Server.Middleware;
using OpenCertServer.Acme.Server.Services;
using OpenCertServer.CertServer;
using OpenCertServer.CertServer.Tests;
using OpenCertServer.Est.Server;
using TechTalk.SpecFlow;
using Xunit;

namespace StepDefinitions;

[Binding]
public partial class CertificateServerFeatures
{
    private TestServer _server = null!;
    private IAcmeClient _client = null!;
    private PlacedOrder _placedOrder = null!;

    [Given(@"a certificate server")]
    public void GivenACertificateServer()
    {
        _server = new TestServer(
            WebHost.CreateDefaultBuilder()
                .UseUrls("http://localhost")
                .ConfigureAppConfiguration(c => c.AddEnvironmentVariables())
                .ConfigureServices(
                    (ctx, services) => services.AddEstServer(new X500DistinguishedName("CN=reimers.io"))
                        .AddAcmeServer(
                            ctx.Configuration,
                            _ => _server!.CreateClient(),
                            new AcmeServerOptions
                            {
                                HostedWorkers = new BackgroundServiceOptions { EnableIssuanceService = false }
                            })
                        .AddSingleton<ICsrValidator, DefaultCsrValidator>()
                        .AddSingleton<ICertificateIssuer, DefaultIssuer>()
                        .Replace(
                            new ServiceDescriptor(
                                typeof(IValidateHttp01Challenges),
                                typeof(PassAllChallenges),
                                ServiceLifetime.Transient))
                        .AddAcmeInMemoryStore())
                .Configure(app => app.UseAcmeServer().UseEstServer()));
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
                Domains = new[] { "localhost" },
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
