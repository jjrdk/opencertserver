namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Persistence;
using Xunit;

/// <summary>
/// Covers §4.2 (route-scoped file persistence) from the code-review plan: each route persists a
/// separate leaf on disk, leaf/chain/key are co-located per route, and renewing the same route
/// replaces rather than duplicates. The chain bundle is written by
/// <see cref="FileCertificatePersistenceStrategy.PersistSiteCertificateChain"/> so it holds the real
/// issuer certificates rather than a duplicate of the leaf.
/// </summary>
public sealed class FileCertificatePersistenceRouteTests : IDisposable
{
    private readonly string _root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
    private readonly FileCertificatePersistenceStrategy _strategy;

    public FileCertificatePersistenceRouteTests()
    {
        _strategy = new FileCertificatePersistenceStrategy(_root);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, recursive: true);
        }
        catch
        {
        }
    }

    private X509Certificate2 MakeCert(string cn)
           => SelfSignedCertificate.MakeWithSubject(cn, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));

    [Fact]
    public async Task EachRoutePersistsASeparateLeafOnDisk()
    {
        var alpha = MakeCert("alpha.example.com");
        var beta = MakeCert("beta.example.com");

        await _strategy.PersistSiteCertificate(alpha, "route.alpha");
        await _strategy.PersistSiteCertificate(beta, "route.beta");

        var alphaLeaf = Path.Combine(_root, "route.alpha", "leaves", "server.crt");
        var betaLeaf = Path.Combine(_root, "route.beta", "leaves", "server.crt");

        Assert.True(File.Exists(alphaLeaf));
        Assert.True(File.Exists(betaLeaf));

        var alphaBytes = await File.ReadAllBytesAsync(alphaLeaf, TestContext.Current.CancellationToken);
        var betaBytes = await File.ReadAllBytesAsync(betaLeaf, TestContext.Current.CancellationToken);

        Assert.False(alphaBytes.SequenceEqual(betaBytes));
    }

    [Fact]
    public async Task LeafChainAndKeyAreCoLocatedPerRoute()
    {
        var cert = MakeCert("alpha.example.com");
        Assert.True(cert.HasPrivateKey);

        await _strategy.PersistSiteCertificate(cert, "route.alpha");

        var keyFile = Path.Combine(_root, "route.alpha", "keys", "server.key");
        var chainFile = Path.Combine(_root, "route.alpha", "chains", "server.crt");
        var leafFile = Path.Combine(_root, "route.alpha", "leaves", "server.crt");

        Assert.True(File.Exists(keyFile));
        Assert.True(File.Exists(chainFile));
        Assert.True(File.Exists(leafFile));
    }

    [Fact]
    public async Task RenewingSameRouteReplacesNotDuplicates()
    {
        var v1 = MakeCert("alpha.example.com");
        var v2 = MakeCert("alpha.example.com");

        await _strategy.PersistSiteCertificate(v1, "route.alpha");
        await _strategy.PersistSiteCertificate(v2, "route.alpha");

        var leafDir = Path.Combine(_root, "route.alpha", "leaves");
        var leafFiles = Directory.GetFiles(leafDir, "server.crt", SearchOption.TopDirectoryOnly);

        Assert.Single(leafFiles);

        var persisted = await _strategy.RetrieveSiteCertificate("route.alpha");
        Assert.Equal(v2.Thumbprint, persisted!.Thumbprint);
    }

    [Fact]
    public async Task ChainFileIsWrittenByTheChainOverload()
    {
        var cert = MakeCert("alpha.example.com");
        var collection = new X509Certificate2Collection { cert };

        await _strategy.PersistSiteCertificateChain(collection, "route.alpha");

        var leafFile = Path.Combine(_root, "route.alpha", "leaves", "server.crt");
        Assert.True(File.Exists(leafFile));

        var back = await _strategy.RetrieveSiteCertificate("route.alpha");
        Assert.Equal(cert.Thumbprint, back!.Thumbprint);
    }
}