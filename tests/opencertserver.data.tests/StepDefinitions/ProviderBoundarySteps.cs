using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Migrations;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Storage;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Data;
using Reqnroll;
using Xunit;

namespace opencertserver.data.tests.StepDefinitions;

[Binding]
public sealed class ProviderBoundarySteps
{
    [Then("the shared data assembly has no database engine dependency")]
    public void SharedAssemblyIsProviderIndependent()
    {
        var assembly = typeof(CaDbContext).Assembly;
        Assert.DoesNotContain(assembly.GetReferencedAssemblies(),
            reference => reference.Name?.Contains("Npgsql", StringComparison.OrdinalIgnoreCase) == true
                || reference.Name?.Contains("SqlServer", StringComparison.OrdinalIgnoreCase) == true
                || reference.Name?.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) == true);
        Assert.DoesNotContain(assembly.GetTypes(),
            type => typeof(Migration).IsAssignableFrom(type) || typeof(ModelSnapshot).IsAssignableFrom(type));
    }

    [Then("relational registration requires an explicit provider")]
    public void MissingProviderFailsClosed()
    {
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddAcmeRelationalStore("test"));
        Assert.Throws<InvalidOperationException>(() => new ServiceCollection().AddCaRelationalStore("test"));
    }

    [Then("database-specific operations use the injected provider")]
    public async Task ProviderOperationsAreDispatched()
    {
        var adapter = new ProbeProvider();
        var services = new ServiceCollection();
        services.AddSingleton<IRelationalStoreProvider>(adapter);
        services.AddAcmeRelationalStore("engine-independent").AddCaRelationalStore("engine-independent");
        Assert.Throws<InvalidOperationException>(() => services.AddCaRelationalStore("different-database"));
        await using var provider = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
        var nonces = provider.GetRequiredService<INonceStore>();
        var nonce = new Nonce("dispatch-test");
        await nonces.SaveNonceAsync(nonce, TestContext.Current.CancellationToken);
        Assert.True(await nonces.TryRemoveNonceAsync(nonce, TestContext.Current.CancellationToken));
        Assert.False(await nonces.TryRemoveNonceAsync(nonce, TestContext.Current.CancellationToken));
        var certificates = provider.GetRequiredService<IStoreCertificates>();
        Assert.True(await certificates.RemoveCertificate("01", X509RevocationReason.KeyCompromise,
            TestContext.Current.CancellationToken));
        Assert.Equal("01", Assert.Single(await certificates.GetInventory(2, 3,
            TestContext.Current.CancellationToken).ToListAsync(TestContext.Current.CancellationToken)).SerialNumber);
        Assert.Equal("01", Assert.Single(await certificates.GetRevocationList(4, 5,
            TestContext.Current.CancellationToken).ToListAsync(TestContext.Current.CancellationToken)).SerialNumber);
        Assert.Equal("engine-independent", adapter.Connection);
        Assert.Equal(6, adapter.Configurations);
        Assert.Equal(new[] { (2, 3, false), (4, 5, true) }, adapter.Pages);
        Assert.Equal(("01", X509RevocationReason.KeyCompromise), adapter.Revocation);
    }

    private sealed class ProbeProvider : IRelationalStoreProvider
    {
        private readonly HashSet<string> _tokens = [];
        public string? Connection { get; private set; }
        public int Configurations { get; private set; }
        public List<(int, int, bool)> Pages { get; } = [];
        public (string, X509RevocationReason)? Revocation { get; private set; }

        public void Configure(DbContextOptionsBuilder options, string connectionString)
        {
            Connection = connectionString;
            Configurations++;
        }

        public bool IsUniqueViolation(DbUpdateException exception) => false;

        public Task SaveNonceAsync(CaDbContext context, Nonce nonce, CancellationToken cancellationToken)
        {
            _tokens.Add(nonce.Token);
            return Task.CompletedTask;
        }

        public Task<bool> TryRemoveNonceAsync(CaDbContext context, Nonce nonce, CancellationToken cancellationToken) =>
            Task.FromResult(_tokens.Remove(nonce.Token));

        public Task<bool> RevokeCertificateAsync(CaDbContext context, string serialNumber,
            X509RevocationReason reason, CancellationToken cancellationToken)
        {
            Revocation = (serialNumber, reason);
            return Task.FromResult(true);
        }

        public async IAsyncEnumerable<CertificateItemInfo> ReadCertificatePage(CaDbContext context,
            int page, int pageSize, bool revokedOnly,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            Pages.Add((page, pageSize, revokedOnly));
            await Task.CompletedTask;
            yield return new CertificateItemInfo
            {
                SerialNumber = "01", DistinguishedName = "CN=probe", Thumbprint = "probe"
            };
        }
    }
}
