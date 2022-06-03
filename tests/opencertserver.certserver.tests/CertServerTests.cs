namespace OpenCertServer.CertServer.Tests;

using System.Security.Cryptography.X509Certificates;
using Acme.Abstractions.IssuanceServices;
using Acme.Abstractions.Services;
using Acme.Abstractions.Storage;
using Acme.AspNetClient.Certes;
using Acme.AspNetClient.Persistence;
using Acme.Server.Configuration;
using Acme.Server.Extensions;
using Acme.Server.Middleware;
using Acme.Server.Services;
using Ca;
using Certes;
using Est.Server;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging.Abstractions;
using opencertserver.certserver;
using Xunit;

public class CertServerTests : IDisposable
{
    private readonly TestServer _server;

    public CertServerTests()
    {
        _server = new TestServer(
            WebHost.CreateDefaultBuilder().UseUrls("http://localhost")
                .ConfigureAppConfiguration(c => c.AddEnvironmentVariables())
                .ConfigureServices(
                    (ctx, services) => services
                        .AddEstServer(new X500DistinguishedName("CN=reimers.io"))
                        .AddAcmeServer(ctx.Configuration, _ => _server!.CreateClient(), new AcmeServerOptions { HostedWorkers = new BackgroundServiceOptions { EnableIssuanceService = false } })
                        .AddSingleton<ICsrValidator, DefaultCsrValidator>()
                        .AddSingleton<ICertificateIssuer, DefaultIssuer>()
                        .Replace(new ServiceDescriptor(typeof(IHttp01ChallengeValidator), typeof(PassAllChallengeValidator), ServiceLifetime.Transient))
                        .AddSingleton<IOrderStore, InMemoryOrderStore>()
                        .AddSingleton<INonceStore, InMemoryNonceStore>()
                        .AddSingleton<IAccountStore, InMemoryAccountStore>()
                    )
                .Configure(app => app.UseAcmeServer().UseEstServer()));
    }

    [Theory]
    [InlineData(KeyAlgorithm.RS256)]
    [InlineData(KeyAlgorithm.ES256)]
    [InlineData(KeyAlgorithm.ES384)]
    [InlineData(KeyAlgorithm.ES512)]
    public async Task CanCompleteCertificateFlow(KeyAlgorithm keyAlgorithm)
    {
        var factory = new AcmeClientFactory(
            new PersistenceService(
                new List<ICertificatePersistenceStrategy> { new MemoryCertificatePersistenceStrategy() },
                new List<IChallengePersistenceStrategy> { new MemoryChallengePersistenceStrategy() },
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

        var client = await factory.GetClient();

        var placedOrder = await client.PlaceOrder("localhost");
        var cert = await client.FinalizeOrder(placedOrder);

        Assert.NotNull(cert);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _server.Host.StopAsync().Wait();
        _server.Dispose();
        GC.SuppressFinalize(this);
    }
}