using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using CertesSlim.Acme;
using CertesSlim.Acme.Resource;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Acme.Abstractions.Exceptions;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Storage;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Data;
using OpenCertServer.Data.PostgreSql;
using OpenCertServer.Testing;
using opencertserver.data.tests.Support;
using Reqnroll;
using Xunit;

namespace opencertserver.data.tests.StepDefinitions;

using Account = OpenCertServer.Acme.Abstractions.Model.Account;
using Order = OpenCertServer.Acme.Abstractions.Model.Order;

[Binding]
public sealed class RelationalStoresSteps
{
    private RelationalTestDatabase? _database;
    private ServiceProvider _services = null!;
    private string _connection = null!;
    private readonly List<X509Certificate2> _certificates = [];
    private Account _account = null!;
    private Order _order = null!;
    private ExternalAccountKey _key = null!;
    private ExternalAccountKey _staleKey = null!;

    private IStoreAccounts Accounts => _services.GetRequiredService<IStoreAccounts>();
    private IStoreOrders Orders => _services.GetRequiredService<IStoreOrders>();
    private INonceStore Nonces => _services.GetRequiredService<INonceStore>();
    private IStoreExternalAccountKeys Keys => _services.GetRequiredService<IStoreExternalAccountKeys>();
    private IStoreCertificates Certificates => _services.GetRequiredService<IStoreCertificates>();

    [Given("the relational database is {string}")]
    public async Task StartDatabase(string database)
    {
        _database = new RelationalTestDatabase(database);
        await _database.StartAsync(TestContext.Current.CancellationToken);
        _connection = _database.ConnectionString;
        _services = CreateServices();
    }

    private ServiceProvider CreateServices()
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:TestDatabase"] = _connection
        }).Build();
        var services = new ServiceCollection();
        services.AddAcmeInMemoryStore();
        services.AddSingleton<IStoreCertificates, InMemoryCertificateStore>();
        _database!.RegisterProvider(services)
            .AddAcmeRelationalStore(config, "TestDatabase")
            .AddCaRelationalStore(config, "TestDatabase");
        return services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
    }

    private async Task Reload()
    {
        await _services.DisposeAsync();
        _services = CreateServices();
    }

    [AfterScenario]
    public async Task Dispose()
    {
        foreach (var certificate in _certificates) certificate.Dispose();
        if (_services is not null)
        {
            await _services.DisposeAsync();
        }

        if (_database is not null)
        {
            await _database.DisposeAsync();
        }
    }

    [Then("accounts round trip and support contact updates and key rollover")]
    public async Task AccountRoundTrip()
    {
        Assert.Null(await Accounts.LoadAccount("missing", TestContext.Current.CancellationToken));
        _account = TestData.NewAccount();
        await Accounts.SaveAccount(_account, TestContext.Current.CancellationToken);
        Assert.True(_account.Version > 0);
        var originalJwk = _account.Jwk;
        var duplicate = new Account(originalJwk, [], null);
        await Assert.ThrowsAsync<ConcurrencyException>(() => Accounts.SaveAccount(duplicate, TestContext.Current.CancellationToken));
        Assert.Equal(0, duplicate.Version);
        await Reload();
        var loaded = Assert.IsType<Account>(await Accounts.FindAccount(originalJwk, TestContext.Current.CancellationToken));
        Assert.Equal(_account.AccountId, loaded.AccountId);
        Assert.Equal(_account.ExternalAccountId, loaded.ExternalAccountId);
        Assert.Equal(_account.Contacts, loaded.Contacts);
        Assert.Equal(_account.TosAccepted, loaded.TosAccepted);
        Assert.Equal(_account.AccountUri, loaded.AccountUri);
        Assert.Equal(_account.Version, loaded.Version);
        loaded.UpdateContacts(["mailto:updated@example.com"]);
        loaded.ReplaceKey(TestData.NewAccount().Jwk);
        await Accounts.SaveAccount(loaded, TestContext.Current.CancellationToken);
        Assert.Null(await Accounts.FindAccount(originalJwk, TestContext.Current.CancellationToken));
        var updated = Assert.IsType<Account>(await Accounts.FindAccount(loaded.Jwk, TestContext.Current.CancellationToken));
        Assert.Equal(loaded.Contacts, updated.Contacts);
        Assert.Equal(loaded.Version, updated.Version);
        _account = updated;
    }

    [Then("concurrent account updates reject stale versions")]
    public async Task AccountConcurrency()
    {
        var stale = Assert.IsType<Account>(await Accounts.LoadAccount(_account.AccountId, TestContext.Current.CancellationToken));
        _account.Deactivate();
        await Accounts.SaveAccount(_account, TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<ConcurrencyException>(() => Accounts.SaveAccount(stale, TestContext.Current.CancellationToken));
        var stored = Assert.IsType<Account>(await Accounts.LoadAccount(_account.AccountId, TestContext.Current.CancellationToken));
        Assert.Equal(AccountStatus.Deactivated, stored.Status);
        Assert.Equal(_account.Version, stored.Version);
    }

    [Then("orders preserve identities and parent references after reload")]
    public async Task OrderRoundTrip()
    {
        Assert.Null(await Orders.LoadOrder("missing", TestContext.Current.CancellationToken));
        _account = TestData.NewAccount();
        await Accounts.SaveAccount(_account, TestContext.Current.CancellationToken);
        _order = TestData.NewOrder(_account);
        await Orders.SaveOrder(_order, TestContext.Current.CancellationToken);
        await Reload();
        var loaded = Assert.IsType<Order>(await Orders.LoadOrder(_order.OrderId, TestContext.Current.CancellationToken));
        Assert.Equal(_order.OrderId, loaded.OrderId);
        Assert.Equal(_order.AccountId, loaded.AccountId);
        Assert.Equal(_order.Profile, loaded.Profile);
        Assert.Equal(_order.Expires, loaded.Expires);
        Assert.Equal(_order.NotBefore, loaded.NotBefore);
        Assert.Equal(_order.NotAfter, loaded.NotAfter);
        var authorization = Assert.Single(loaded.Authorizations);
        var challenge = Assert.Single(authorization.Challenges);
        Assert.Equal(_order.Authorizations[0].AuthorizationId, authorization.AuthorizationId);
        Assert.Equal(_order.Authorizations[0].Challenges[0].ChallengeId, challenge.ChallengeId);
        Assert.Equal(_order.Authorizations[0].Challenges[0].Token, challenge.Token);
        Assert.Equal("valid.example", authorization.Identifier.Value);
        Assert.Same(loaded, authorization.Order);
        Assert.Same(authorization, challenge.Authorization);
        Assert.Contains(loaded.OrderId, await Orders.GetOrderIds(_account.AccountId, TestContext.Current.CancellationToken));
        Assert.Empty(await Orders.GetOrderIds("unrelated", TestContext.Current.CancellationToken));
        _order = loaded;
    }

    [Then("only orders with processing challenges are validatable")]
    public async Task ValidationLifecycle()
    {
        Assert.Empty(await Orders.GetValidatableOrders(TestContext.Current.CancellationToken));
        var challenge = _order.Authorizations[0].Challenges[0];
        challenge.SetStatus(ChallengeStatus.Processing);
        challenge.ExtraData = """{"attestation":"evidence"}""";
        await Orders.SaveOrder(_order, TestContext.Current.CancellationToken);
        var processing = Assert.Single(await Orders.GetValidatableOrders(TestContext.Current.CancellationToken));
        Assert.Equal(_order.OrderId, processing.OrderId);
        Assert.Equal(challenge.ExtraData, processing.Authorizations[0].Challenges[0].ExtraData);
        challenge.SetStatus(ChallengeStatus.Valid);
        challenge.Validated = DateTimeOffset.UtcNow;
        _order.Authorizations[0].SetStatus(AuthorizationStatus.Valid);
        _order.SetStatusFromAuthorizations();
        await Orders.SaveOrder(_order, TestContext.Current.CancellationToken);
        Assert.Empty(await Orders.GetValidatableOrders(TestContext.Current.CancellationToken));
    }

    [Then("order updates preserve issuance data and reject stale versions")]
    public async Task OrderUpdate()
    {
        var stale = Assert.IsType<Order>(await Orders.LoadOrder(_order.OrderId, TestContext.Current.CancellationToken));
        _order.SetStatus(OrderStatus.Processing);
        _order.CertificateSigningRequest = "stored-csr";
        _order.Certificate = [1, 2, 3];
        _order.Error = new AcmeError { Type = "test", Detail = "stored error", Identifier = _order.Identifiers[0] };
        _order.SetStatus(OrderStatus.Valid);
        await Orders.SaveOrder(_order, TestContext.Current.CancellationToken);
        await Assert.ThrowsAsync<ConcurrencyException>(() => Orders.SaveOrder(stale, TestContext.Current.CancellationToken));
        await Reload();
        var stored = Assert.IsType<Order>(await Orders.LoadOrder(_order.OrderId, TestContext.Current.CancellationToken));
        Assert.Equal(OrderStatus.Valid, stored.Status);
        Assert.Equal(_order.Certificate, stored.Certificate);
        Assert.Equal(_order.CertificateSigningRequest, stored.CertificateSigningRequest);
        Assert.Equal(_order.Error.Detail, stored.Error?.Detail);
        Assert.Equal(_order.Authorizations[0].Challenges[0].Validated, stored.Authorizations[0].Challenges[0].Validated);
    }

    [Then("concurrent nonce consumers have exactly one winner")]
    public async Task ConsumeNonce()
    {
        var nonce = new Nonce("AbC-single-use");
        await Task.WhenAll(Enumerable.Range(0, 10).Select(_ => Nonces.SaveNonceAsync(nonce, TestContext.Current.CancellationToken)));
        await Reload();
        var results = await Task.WhenAll(Enumerable.Range(0, 20).Select(_ => Nonces.TryRemoveNonceAsync(nonce, TestContext.Current.CancellationToken)));
        Assert.Equal(1, results.Count(r => r));
        Assert.False(await Nonces.TryRemoveNonceAsync(nonce, TestContext.Current.CancellationToken));
    }

    [Then("nonce tokens are case sensitive")]
    public async Task NonceCase()
    {
        await Nonces.SaveNonceAsync(new Nonce("CaseSensitive"), TestContext.Current.CancellationToken);
        Assert.False(await Nonces.TryRemoveNonceAsync(new Nonce("casesensitive"), TestContext.Current.CancellationToken));
        Assert.True(await Nonces.TryRemoveNonceAsync(new Nonce("CaseSensitive"), TestContext.Current.CancellationToken));
    }

    [Then("cancelled store operations propagate cancellation")]
    public async Task Cancellation()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Accounts.LoadAccount("missing", cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Orders.LoadOrder("missing", cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Nonces.SaveNonceAsync(new Nonce("cancelled"), cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Nonces.TryRemoveNonceAsync(new Nonce("cancelled"), cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Keys.LoadKey("missing", cancelled.Token));
        var certificateId = CertId.Create(NewCertificate(42), HashAlgorithmName.SHA256);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Certificates.GetCertificateStatus(certificateId, cancelled.Token));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Certificates.GetInventory(cancellationToken: cancelled.Token)
            .ToListAsync(cancelled.Token).AsTask());
    }

    [Then("external account keys preserve binding metadata across reloads")]
    public async Task ExternalKeyRoundTrip()
    {
        Assert.Null(await Keys.LoadKey("missing", TestContext.Current.CancellationToken));
        _key = new ExternalAccountKey("eab", Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), "HS384");
        await Keys.SaveKey(_key, TestContext.Current.CancellationToken);
        _staleKey = Assert.IsType<ExternalAccountKey>(await Keys.FindActiveKey(_key.KeyId, TestContext.Current.CancellationToken));
        _key.MarkUsed("account");
        await Keys.SaveKey(_key, TestContext.Current.CancellationToken);
        await Reload();
        Assert.Null(await Keys.FindActiveKey(_key.KeyId, TestContext.Current.CancellationToken));
        var stored = Assert.IsType<ExternalAccountKey>(await Keys.LoadKey(_key.KeyId, TestContext.Current.CancellationToken));
        Assert.True(stored.IsUsed);
        Assert.Equal(_key.BoundAt, stored.BoundAt);
        Assert.Equal(_key.BoundAccountId, stored.BoundAccountId);
        Assert.Equal(_key.MacKey, stored.MacKey);
        Assert.Equal(_key.MacAlgorithm, stored.MacAlgorithm);
        Assert.Equal(_key.Version, stored.Version);
    }

    [Then("stale external account key consumers cannot overwrite the binding")]
    public async Task ExternalKeyConcurrency()
    {
        _staleKey.MarkUsed("different-account");
        await Assert.ThrowsAsync<ConcurrencyException>(() => Keys.SaveKey(_staleKey, TestContext.Current.CancellationToken));
        Assert.Equal("account", (await Keys.LoadKey(_key.KeyId, TestContext.Current.CancellationToken))?.BoundAccountId);
    }

    private X509Certificate2 NewCertificate(int serial)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest($"CN=certificate-{serial}.example", key, HashAlgorithmName.SHA256);
        using var issuer = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var certificate = request.Create(issuer.SubjectName,
            X509SignatureGenerator.CreateForECDsa(key),
            DateTimeOffset.UtcNow.AddHours(-1), DateTimeOffset.UtcNow.AddDays(2),
            [(byte)(serial >> 8), (byte)serial]);
        _certificates.Add(certificate);
        return certificate;
    }

    [Then("certificate lookup and OCSP status survive reloads")]
    public async Task CertificateRoundTrip()
    {
        var certificate = NewCertificate(0xABCD);
        await Certificates.AddCertificate(certificate, TestContext.Current.CancellationToken);
        await Reload();
        var id = CertId.Create(certificate, HashAlgorithmName.SHA256);
        Assert.Equal(CertificateStatus.Good, (await Certificates.GetCertificateStatus(id, TestContext.Current.CancellationToken)).Item2);
        var byId = await Certificates.GetCertificatesById(TestContext.Current.CancellationToken, certificate.SerialNumberBytes).ToListAsync(TestContext.Current.CancellationToken);
        using var foundById = Assert.Single(byId);
        Assert.Equal(certificate.RawData, foundById.RawData);
        Assert.False(foundById.HasPrivateKey);
        var byThumbprint = await Certificates.GetCertificatesByThumbprint([certificate.Thumbprint.ToLowerInvariant().AsMemory()], TestContext.Current.CancellationToken).ToListAsync(TestContext.Current.CancellationToken);
        using var foundByThumbprint = Assert.Single(byThumbprint);
        Assert.Equal(certificate.RawData, foundByThumbprint.RawData);
        var inventory = Assert.Single(await Certificates.GetInventory(cancellationToken: TestContext.Current.CancellationToken).ToListAsync(TestContext.Current.CancellationToken));
        Assert.Equal(DateTimeKind.Utc, inventory.NotBefore.DateTime.Kind);
        Assert.Equal(DateTimeKind.Utc, inventory.NotAfter.DateTime.Kind);
        Assert.True(await Certificates.RemoveCertificate(certificate.SerialNumber, X509RevocationReason.KeyCompromise, TestContext.Current.CancellationToken));
        await Reload();
        var revoked = await Certificates.GetCertificateStatus(id, TestContext.Current.CancellationToken);
        Assert.Equal(CertificateStatus.Revoked, revoked.Item2);
        Assert.NotNull(revoked.Item3);
        Assert.False(await Certificates.RemoveCertificate("missing", X509RevocationReason.Unspecified, TestContext.Current.CancellationToken));
        Assert.Equal(CertificateStatus.Unknown, (await Certificates.GetCertificateStatus(CertId.Create(NewCertificate(999), HashAlgorithmName.SHA256), TestContext.Current.CancellationToken)).Item2);
    }

    [Then("paginated inventory and revocations match the memory store")]
    public async Task CertificatePagination()
    {
        var memory = new InMemoryCertificateStore();
        // Include the certificate already recorded by the preceding step.
        await memory.AddCertificate(_certificates[0], TestContext.Current.CancellationToken);
        await memory.RemoveCertificate(_certificates[0].SerialNumber, X509RevocationReason.KeyCompromise, TestContext.Current.CancellationToken);
        for (var i = 1; i <= 105; i++)
        {
            var certificate = NewCertificate(i);
            await Certificates.AddCertificate(certificate, TestContext.Current.CancellationToken);
            await memory.AddCertificate(certificate, TestContext.Current.CancellationToken);
            await Certificates.RemoveCertificate(certificate.SerialNumber, X509RevocationReason.Superseded, TestContext.Current.CancellationToken);
            await memory.RemoveCertificate(certificate.SerialNumber, X509RevocationReason.Superseded, TestContext.Current.CancellationToken);
        }
        for (var page = 0; page < 4; page++)
        {
            var expected = await memory.GetInventory(page, 40, TestContext.Current.CancellationToken).ToListAsync(TestContext.Current.CancellationToken);
            var actual = await Certificates.GetInventory(page, 40, TestContext.Current.CancellationToken).ToListAsync(TestContext.Current.CancellationToken);
            Assert.Equal(expected.Select(c => c.SerialNumber), actual.Select(c => c.SerialNumber));
            Assert.Equal(expected.Select(c => c.RevocationReason), actual.Select(c => c.RevocationReason));
            var expectedRevoked = await memory.GetRevocationList(null, page, 40, TestContext.Current.CancellationToken).ToListAsync(TestContext.Current.CancellationToken);
            var actualRevoked = await Certificates.GetRevocationList(null, page, 40, TestContext.Current.CancellationToken).ToListAsync(TestContext.Current.CancellationToken);
            Assert.Equal(expectedRevoked.Select(c => c.SerialNumber), actualRevoked.Select(c => c.SerialNumber));
        }
    }

    [Then("applying the migrations again preserves stored accounts")]
    public async Task Migrations()
    {
        var account = TestData.NewAccount();
        await Accounts.SaveAccount(account, TestContext.Current.CancellationToken);
        await _database!.MigrateAsync(TestContext.Current.CancellationToken);
        await Reload();
        Assert.Equal(account.AccountId, (await Accounts.LoadAccount(account.AccountId, TestContext.Current.CancellationToken))?.AccountId);
        await using var scope = _services.CreateAsyncScope();
        Assert.False(scope.ServiceProvider.GetRequiredService<CaDbContext>().Database.HasPendingModelChanges());
    }

    [Then("omitting relational registration preserves the existing stores")]
    public void Defaults()
    {
        var services = new ServiceCollection().AddAcmeInMemoryStore();
        services.AddSingleton<IStoreCertificates, InMemoryCertificateStore>();
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(CaDbContext));
        using var provider = services.BuildServiceProvider();
        Assert.IsType<InMemoryCertificateStore>(provider.GetRequiredService<IStoreCertificates>());
        Assert.DoesNotContain("Relational", provider.GetRequiredService<IStoreAccounts>().GetType().Name);
    }

    [Then("explicit relational registration uses the named standard connection regardless of persistence settings")]
    public void NamedConnection()
    {
        foreach (var mode in new[] { "file", "memory", "relational" })
        {
            const string connection = "Host=selected;Database=test";
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AcmeServer:Persistence"] = mode, ["Ca:Persistence"] = mode,
                ["ConnectionStrings:Selected"] = connection,
                ["ConnectionStrings:Other"] = "Host=other",
                ["AcmeServer:Relational:Connection"] = "Host=legacy",
                ["OCS_RELATIONAL_CONN"] = "Host=legacy"
            }).Build();
            var services = new ServiceCollection().AddAcmeInMemoryStore();
            services.AddSingleton<IStoreCertificates, InMemoryCertificateStore>();
            services.AddPostgreSqlStore()
                .AddAcmeRelationalStore(configuration, "Selected")
                .AddCaRelationalStore(configuration, "Selected");
            using var provider = services.BuildServiceProvider();
            using var scope = provider.CreateScope();
            Assert.Equal(connection, scope.ServiceProvider.GetRequiredService<CaDbContext>().Database.GetConnectionString());
            Assert.IsType<OpenCertServer.Data.Stores.RelationalAccountStore>(provider.GetRequiredService<IStoreAccounts>());
            Assert.IsType<OpenCertServer.Data.Stores.RelationalCertificateStore>(provider.GetRequiredService<IStoreCertificates>());
        }
    }

    [Then("invalid relational configuration is rejected")]
    public void InvalidConfiguration()
    {
        foreach (var value in new[] { null, "", " " })
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:Missing"] = value,
                ["AcmeServer:Relational:Connection"] = "Host=legacy",
                ["Ca:Relational:Connection"] = "Host=legacy",
                ["OCS_RELATIONAL_CONN"] = "Host=legacy"
            }).Build();
            var services = new ServiceCollection().AddPostgreSqlStore();
            Assert.Contains("ConnectionStrings:Missing", Assert.Throws<InvalidOperationException>(
                () => services.AddAcmeRelationalStore(configuration, "Missing")).Message);
            Assert.Throws<InvalidOperationException>(() => services.AddCaRelationalStore(configuration, "Missing"));
            Assert.Throws<ArgumentException>(() => services.AddAcmeRelationalStore(configuration, " "));
            Assert.Throws<ArgumentException>(() => services.AddCaRelationalStore(configuration, ""));
            Assert.DoesNotContain(services, d => d.ServiceType == typeof(CaDbContext));
        }
        var connections = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["ConnectionStrings:Acme"] = "Host=first",
            ["ConnectionStrings:Ca"] = "Host=second"
        }).Build();
        var registered = new ServiceCollection().AddPostgreSqlStore().AddAcmeRelationalStore(connections, "Acme");
        Assert.Throws<InvalidOperationException>(() => registered.AddCaRelationalStore(connections, "Ca"));
    }

    [Then("migration tooling reads named standard connection strings")]
    public void MigrationConnection()
    {
        var name = $"MigrationTest_{Guid.NewGuid():N}";
        var variable = $"ConnectionStrings__{name}";
        const string connection = "Host=migrations;Database=test";
        try
        {
            Environment.SetEnvironmentVariable(variable, connection);
            using (var context = new CaDbContextFactory().CreateDbContext([name]))
            {
                Assert.Equal(connection, context.Database.GetConnectionString());
            }
            Environment.SetEnvironmentVariable(variable, " ");
            Assert.Contains($"ConnectionStrings:{name}", Assert.Throws<InvalidOperationException>(
                () => new CaDbContextFactory().CreateDbContext([name])).Message);
            Environment.SetEnvironmentVariable(variable, null);
            Assert.Throws<InvalidOperationException>(() => new CaDbContextFactory().CreateDbContext([name]));
        }
        finally
        {
            Environment.SetEnvironmentVariable(variable, null);
        }
    }

    private static async Task<string> RunProcess(ProcessStartInfo start, TimeSpan timeout)
    {
        start.RedirectStandardOutput = true;
        start.RedirectStandardError = true;
        start.UseShellExecute = false;
        using var process = Process.Start(start) ?? throw new InvalidOperationException($"Could not start {start.FileName}.");
        var stdout = process.StandardOutput.ReadToEndAsync();
        var stderr = process.StandardError.ReadToEndAsync();
        using var cancellation = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(cancellation.Token);
        }
        catch (OperationCanceledException)
        {
            process.Kill(entireProcessTree: true);
            await process.WaitForExitAsync();
            throw;
        }
        var output = await stdout + await stderr;
        Assert.True(process.ExitCode == 0, $"{start.FileName} exited with {process.ExitCode}:\n{output}");
        return output;
    }
}
