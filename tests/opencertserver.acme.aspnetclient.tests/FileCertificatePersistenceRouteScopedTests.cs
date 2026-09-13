namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Persistence;
using Xunit;

/// <summary>
/// Covers §4.2 (per-route certificate storage) of the YARP reverse-proxy ACME compatibility
/// plan: each route keeps its own leaf/chain/key under a route-scoped directory, renewals
/// overwrite rather than duplicate, and distinct routes hold distinct certificates.
/// </summary>
public sealed class FileCertificatePersistenceRouteScopedTests : IDisposable
{
    private readonly string _root;
    private readonly FileCertificatePersistenceStrategy _strategy;

    public FileCertificatePersistenceRouteScopedTests()
    {
        _root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString());
        _strategy = new FileCertificatePersistenceStrategy(_root);
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_root, true);
        }
        catch
        {
        }
    }

    private static X509Certificate2 MakeCert(DateTimeOffset notBefore, DateTimeOffset notAfter)
        => SelfSignedCertificate.MakeWithSubject("route", notBefore, notAfter);

    [Fact]
    public async Task EachRoutePersistsASeparateLeafCertificateOnDisk()
    {
        var alpha = MakeCert(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
        var beta = MakeCert(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(91));

        await _strategy.PersistSiteCertificate(alpha, "route.alpha");
        await _strategy.PersistSiteCertificate(beta, "route.beta");

        var alphaLeaf = Path.Combine(_root, "route.alpha", "leaves", "server.crt");
        var betaLeaf = Path.Combine(_root, "route.beta", "leaves", "server.crt");

        Assert.True(File.Exists(alphaLeaf));
        Assert.True(File.Exists(betaLeaf));

        var alphaBytes = await File.ReadAllBytesAsync(alphaLeaf, TestContext.Current.CancellationToken);
        var betaBytes = await File.ReadAllBytesAsync(betaLeaf, TestContext.Current.CancellationToken);

        Assert.NotEqual(alphaBytes, betaBytes);

        var backAlpha = await _strategy.RetrieveSiteCertificate("route.alpha");
        var backBeta = await _strategy.RetrieveSiteCertificate("route.beta");

        Assert.Equal(alpha.Thumbprint, backAlpha!.Thumbprint);
        Assert.Equal(beta.Thumbprint, backBeta!.Thumbprint);
    }

    [Fact]
    public async Task LeafChainAndKeyAreCoLocatedPerRoute()
    {
        var cert = MakeCert(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
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
    public async Task RenewingTheSameRouteReplacesRatherThanDuplicates()
    {
        var first = MakeCert(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
        var second = MakeCert(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(91));
        var third = MakeCert(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(92));

        await _strategy.PersistSiteCertificate(first, "route.alpha");
        await _strategy.PersistSiteCertificate(second, "route.alpha");
        await _strategy.PersistSiteCertificate(third, "route.alpha");

        var leafDir = Path.Combine(_root, "route.alpha", "leaves");
        var leafFiles = Directory.GetFiles(leafDir, "server.crt", SearchOption.TopDirectoryOnly);

        Assert.Single(leafFiles);

        var mostRecent = await _strategy.RetrieveSiteCertificate("route.alpha");
        Assert.Equal(third.Thumbprint, mostRecent!.Thumbprint);
    }
}
