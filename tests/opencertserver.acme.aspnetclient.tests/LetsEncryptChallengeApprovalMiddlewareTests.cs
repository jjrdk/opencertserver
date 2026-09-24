namespace OpenCertServer.Acme.AspNetClient.Tests;

using CertesSlim.Acme;
using CertesSlim.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

using System;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Certes;
using Microsoft.Extensions.DependencyInjection;
using NSubstitute;
using Persistence;
using Xunit;

public sealed class LetsEncryptChallengeApprovalMiddlewareTests
{
    private static readonly string AcmeToken = Guid.NewGuid().ToString();
    private static readonly string AcmeResponse = $"{Guid.NewGuid()}-{Guid.NewGuid()}";

    private readonly FakeLetsEncryptClient _fakeClient;
    private readonly IHostBuilder _webHostBuilder;

    public LetsEncryptChallengeApprovalMiddlewareTests()
    {
        _fakeClient = new FakeLetsEncryptClient();
        var letsEncryptClientFactory = Substitute.For<IAcmeClientFactory>();
        letsEncryptClientFactory.GetClient().Returns(Task.FromResult<IAcmeClient>(_fakeClient));

        _webHostBuilder = new HostBuilder().ConfigureWebHost(b =>
        {
            b.UseTestServer()
                .ConfigureServices(services =>
                {
                    services.AddAcmeClient(
                            new LetsEncryptOptions
                            {
                                Email = "some-email@github.com",
                                UseStaging = true,
                                Domains = ["test.com"],
                                TimeUntilExpiryBeforeRenewal = TimeSpan.FromDays(30),
                                CertificateSigningRequest = new CsrInfo
                                {
                                    CountryName = "CountryNameStuff",
                                    Locality = "LocalityStuff",
                                    Organization = "OrganizationStuff",
                                    OrganizationUnit = "OrganizationUnitStuff",
                                    State = "StateStuff"
                                },
                                AccountPassword = "test"
                            })
                        .AddAcmeInMemoryCertificatesPersistence()
                        .AddAcmeMemoryChallengePersistence();

                    // mock communication with LetsEncrypt
                    services.Remove(services.Single(x => x.ServiceType == typeof(IAcmeClientFactory)));
                    services.AddSingleton(letsEncryptClientFactory);
                })
                .Configure(app =>
                {
                    app.UseDeveloperExceptionPage()
                        .UseAcmeClient()
                        .Run(async context =>
                        {
                            context.Response.StatusCode = 404;
                            await context.Response.WriteAsync("Not found");
                        });
                })
                .ConfigureLogging(l => l.AddJsonConsole(x => x.IncludeScopes = true));
        });
    }

    [Fact(Skip = "Run manually")]
    public async Task FullFlow()
    {
        using var host = _webHostBuilder.Build();
        host.Start();
        using var server = host.GetTestServer();
        var client = server.CreateClient();

        var initializationTimeout = await Task.WhenAny(Task.Delay(1000, _fakeClient.OrderPlacedCts.Token));
        Assert.True(initializationTimeout.IsCanceled, "Fake LE client initialization timed out");

        var response = await client.GetAsync($"/.well-known/acme-challenge/{AcmeToken}",
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(AcmeResponse, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));

        var finalizationTimeout = await Task.WhenAny(Task.Delay(1000, _fakeClient.OrderFinalizedCts.Token));
        Assert.True(finalizationTimeout.IsCanceled, "Fake LE client finalization timed out");

        var acmeRenewalService = (AcmeRenewalService)server.Services.GetRequiredService<IAcmeRenewalService>();
        var appCert = acmeRenewalService.Certificate?.RawData;
        var fakeCert = FakeLetsEncryptClient.FakeCert.RawData;

        Assert.True(appCert?.SequenceEqual(fakeCert), "Certificates do not match");
    }

    private sealed class FakeLetsEncryptClient : IAcmeClient
    {
        public static readonly X509Certificate2 FakeCert =
            SelfSignedCertificate.Make(DateTime.Now, DateTime.Now.AddDays(90));

        public CancellationTokenSource OrderPlacedCts { get; }
        public CancellationTokenSource OrderFinalizedCts { get; }

        public FakeLetsEncryptClient()
        {
            OrderPlacedCts = new CancellationTokenSource();
            OrderFinalizedCts = new CancellationTokenSource();
        }

        public Task<PlacedOrder> PlaceOrder(ChallengeType challengeType, string[] domains)
        {
            var challengeDtos = new[] { new ChallengeDto(AcmeToken, AcmeResponse, []) };

            OrderPlacedCts.CancelAfter(250);

            return Task.FromResult(new PlacedOrder(
                challengeDtos,
                Substitute.For<IOrderContext>(),
                []));
        }

        public async Task<(X509Certificate2 Certificate, string KeyPem, X509Certificate2Collection Collection)> FinalizeOrder(
            PlacedOrder placedOrder,
            string password,
            string? existingKeyPem = null)
        {
            await Task.Delay(500);

            OrderFinalizedCts.CancelAfter(250);
            var certificate = X509CertificateLoader.LoadCertificate(FakeCert.RawData.AsSpan());
            var keyPem = existingKeyPem ?? ExportKeyPem(certificate);
            var collection = new X509Certificate2Collection { certificate };
            return (certificate, keyPem, collection);
        }

        private static string ExportKeyPem(X509Certificate2 certificate)
        {
            var rsa = certificate.GetRSAPrivateKey();
            if (rsa != null)
            {
                return rsa.ExportRSAPrivateKeyPem();
            }

            var ecdsa = certificate.GetECDsaPrivateKey();
            if (ecdsa != null)
            {
                return ecdsa.ExportECPrivateKeyPem();
            }

            return string.Empty;
        }
    }
}
