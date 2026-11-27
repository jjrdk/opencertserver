using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Ca.Server;
using OpenCertServer.Data;
using OpenCertServer.Data.Stores;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Cryptography.X509Certificates;
using CertesSlim.Extensions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.Abstractions;
using OpenCertServer.Acme.Abstractions.IssuanceServices;
using OpenCertServer.Acme.Abstractions.Services;
using OpenCertServer.Acme.Abstractions.Storage;
using OpenCertServer.Acme.AspNetClient.Certes;
using OpenCertServer.Acme.AspNetClient.Persistence;
using OpenCertServer.Acme.Server;
using OpenCertServer.Acme.Server.Configuration;
using OpenCertServer.Ca;
using OpenCertServer.Testing;
using OpenCertServer.Ca.Utils.Ca;
using Reqnroll;
using Xunit;
using AcmeHeader = OpenCertServer.Acme.Abstractions.HttpModel.Requests.AcmeHeader;

[Binding]
public sealed class RelationalStoreSteps
{
    private RelationalTestDatabase? _database;
    private IHost? _host;
    private TestServer? _server;
    private ServiceProvider? _reloadedServices;
    private IConfigurationRoot? _configuration;
    private CaConfiguration? _caConfiguration;
    private PersistenceService? _clientPersistence;
    private PlacedOrder? _placedOrder;
    private X509Certificate2? _issuedCertificate;
    private string? _orderId;
    private string? _accountId;

    [Given("a relational test server using the {word} provider")]
    public async Task GivenRelationalTestServer(string database)
    {
        _database = new RelationalTestDatabase(database);
        await _database.StartAsync(TestContext.Current.CancellationToken).ConfigureAwait(false);
        _configuration = CreateConfiguration(_database.ConnectionString);
        _caConfiguration = CreateCaConfiguration();
        await _database.SeedProfilesAsync(_database.ConnectionString, _caConfiguration.Profiles,
            TestContext.Current.CancellationToken).ConfigureAwait(false);
        _host = CreateServer();
        await _host.StartAsync().ConfigureAwait(false);
        _server = _host.GetTestServer();
        var storedProfiles = _host.Services.GetRequiredService<IStoreCaProfiles>();
        var configuredProfile = await _caConfiguration.Profiles.GetProfile(null);
        using var storedProfile = await storedProfiles.GetProfile(null);
        Assert.Equal(configuredProfile.Name, storedProfile.Name);
        Assert.Equal(configuredProfile.CertificateChain[0].Thumbprint, storedProfile.CertificateChain[0].Thumbprint);
    }

    [When("an ACME client registers an account and places an order")]
    public async Task WhenAcmeClientRegistersAndPlacesOrder()
    {
        var loggerFactory = NullLoggerFactory.Instance;
        _clientPersistence = new PersistenceService(
            [new InMemoryCertificatePersistenceStrategy()],
            [new InMemoryChallengePersistenceStrategy()],
            NullLogger<PersistenceService>.Instance);
        var clientFactory = new AcmeClientFactory(
            _clientPersistence,
            new TestAcmeOptions
            {
                Profile = "default",
                Email = "relational-store@example.test",
                Domains = ["localhost"],
                KeyAlgorithm = "ES256",
                CertificateSigningRequest = new CsrInfo
                {
                    CommonName = "localhost",
                    CountryName = "DK"
                },
                AccountPassword = "test"
            },
            _server!.CreateClient(),
            loggerFactory);

        var client = await clientFactory.GetClient().ConfigureAwait(false);
        _placedOrder = await client.PlaceOrder(ChallengeType.Http01, ["localhost"]).ConfigureAwait(false);
        var (certificate, _, _) = await client.FinalizeOrder(_placedOrder).ConfigureAwait(false);
        _issuedCertificate = certificate;
        _orderId = _placedOrder.Order.Location.Segments[^1].TrimEnd('/');
        Assert.False(string.IsNullOrWhiteSpace(_orderId));
    }

    [When("the relational service provider is rebuilt")]
    public async Task WhenServiceProviderIsRebuilt()
    {
        await _host!.StopAsync().ConfigureAwait(false);

        var services = new ServiceCollection();
        services.AddLogging();
        ConfigureServices(services, _configuration!, httpClient: null);
        _reloadedServices = services.BuildServiceProvider();
    }

    [Then("the ACME request resolves the same account and order")]
    public async Task ThenAcmeAccountAndOrderAreReloaded()
    {
        var services = _reloadedServices!;
        var orderStore = services.GetRequiredService<IStoreOrders>();
        var order = await orderStore.LoadOrder(_orderId!, CancellationToken.None).ConfigureAwait(false);
        Assert.NotNull(order);
        _accountId = order.AccountId;

        var orderIds = await orderStore.GetOrderIds(_accountId, CancellationToken.None).ConfigureAwait(false);
        Assert.Contains(_orderId, orderIds);

        using var scope = services.CreateScope();
        var account = await scope.ServiceProvider.GetRequiredService<IAccountService>()
            .FromRequest(new AcmeHeader { Kid = $"http://localhost/account/{_accountId}" })
            .ConfigureAwait(false);
        Assert.Equal(_accountId, account.AccountId);
    }

    [When("the CA service revokes the issued certificate")]
    public async Task WhenCaServiceRevokesCertificate()
    {
        var certificateAuthority = _reloadedServices!.GetRequiredService<ICertificateAuthority>();
        var store = _reloadedServices!.GetRequiredService<IStoreCertificates>();
        var issuingProfile = await store.GetIssuingProfile(_issuedCertificate!.Thumbprint,
            TestContext.Current.CancellationToken);
        Assert.NotNull(issuingProfile);
        var revoked = await certificateAuthority.RevokeCertificate(
            _issuedCertificate.GetSerialNumberString(), issuingProfile,
            X509RevocationReason.KeyCompromise).ConfigureAwait(false);
        Assert.True(revoked);
    }

    [Then("the CRL contains the revoked certificate")]
    public async Task ThenCrlContainsCertificate()
    {
        var certificateAuthority = _reloadedServices!.GetRequiredService<ICertificateAuthority>();
        var crl = await certificateAuthority.GetRevocationList().ConfigureAwait(false);
        var builder = CertificateRevocationListBuilder.Load(crl, out _);
        Assert.True(builder.RemoveEntry(Convert.FromHexString(_issuedCertificate!.GetSerialNumberString())));
    }

    [AfterScenario]
    public async Task DisposeScenarioResources()
    {
        _issuedCertificate?.Dispose();

        if (_reloadedServices is not null)
        {
            await _reloadedServices.DisposeAsync().ConfigureAwait(false);
        }

        if (_host is not null)
        {
            _host.Dispose();
        }

        if (_database is not null)
        {
            await _database.DisposeAsync().ConfigureAwait(false);
        }

        _caConfiguration?.Dispose();
    }

    private IHost CreateServer() =>
        new HostBuilder()
            .ConfigureWebHost(builder => builder
                .UseTestServer()
                .UseUrls("http://localhost")
                .ConfigureAppConfiguration(configuration =>
                    configuration.AddConfiguration(_configuration!))
                .ConfigureServices((_, services) => ConfigureServices(
                    services,
                    _configuration!,
                    _ => _server!.CreateClient()))
                .Configure(app => app.UseAcmeServer()))
            .Build();

    private void ConfigureServices(
        IServiceCollection services,
        IConfiguration configuration,
        Func<IServiceProvider, HttpClient>? httpClient)
    {
        _database!.RegisterProvider(services)
            .AddCertificateAuthority(_caConfiguration!)
            .AddAcmeServer(
                configuration,
                httpClient,
                new AcmeServerOptions
                {
                    HostedWorkers = new BackgroundServiceOptions
                    {
                        EnableValidationService = true,
                        EnableIssuanceService = false
                    }
                })
            .AddAcmeRelationalStore(configuration, "OpenCertServer")
            .AddCaRelationalStore(configuration, "OpenCertServer")
            .AddRouting();

        services.AddSingleton<IStoreCaProfiles, RelationalCaProfileStore>();
        services.AddSingleton<TestAcmeChallengeValidationState>();
        services.Replace(ServiceDescriptor.Singleton<IValidateChallenges, TestAcmeHttp01ChallengeValidator>());
        services.Replace(ServiceDescriptor.Singleton<IValidateChallenges, TestAcmeDns01ChallengeValidator>());
        services.Replace(ServiceDescriptor.Singleton<IValidateChallenges,
            TestAcmeDeviceAttestChallengeValidator>());
        services.AddSingleton<ICsrValidator, DefaultCsrValidator>();
        services.AddSingleton(sp => new DefaultIssuer(sp.GetRequiredService<ICertificateAuthority>()));
        services.AddSingleton(sp => new TestAcmeIssuer(sp.GetRequiredService<DefaultIssuer>()));
        services.Replace(ServiceDescriptor.Singleton<IIssueCertificates>(sp =>
            sp.GetRequiredService<TestAcmeIssuer>()));
        services.Replace(ServiceDescriptor.Singleton<IAllowedIdentifiersPolicy>(new TestAllowedIdentifiersPolicy()));
    }

    private static CaConfiguration CreateCaConfiguration()
    {
        var subject = new X500DistinguishedName("CN=Relational Store Test CA");
        var profile = OpenCertServer.Ca.CertificateAuthority.CreateSelfSignedRsa(
            "default",
            subject,
            TimeSpan.FromDays(90));
        return new CaConfiguration(new CaProfileSet("default", profile), [], [], []);
    }

    private static IConfigurationRoot CreateConfiguration(string connectionString) =>
        new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:OpenCertServer"] = connectionString,
                ["AcmeServer:DisableCaaChecks"] = "true"
            })
            .Build();
}
