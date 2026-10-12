namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Persistence;
using Xunit;

/// <summary>
/// Verifies security properties of <see cref="FileCertificatePersistenceStrategy"/>:
/// private keys must not be stored in cleartext and must be recoverable with the correct password.
/// These tests guard against regression of security finding F-03.
/// </summary>
public sealed class FileCertificatePersistenceEncryptionTests : IDisposable
{
    private const string TestPassword = "test-password-F03!";
    private readonly string _root;
    private readonly FileCertificatePersistenceStrategy _strategy;

    public FileCertificatePersistenceEncryptionTests()
    {
        _root = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        _strategy = new FileCertificatePersistenceStrategy(_root, TestPassword);
    }

    public void Dispose()
    {
        try { Directory.Delete(_root, recursive: true); } catch { }
    }

    private static X509Certificate2 MakeCert()
        => SelfSignedCertificate.MakeWithSubject("test", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));

    private static X509Certificate2 MakeRsaCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest("cn=rsa-test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
    }

    // ── Constructor guards ─────────────────────────────────────────────────────────

    [Fact]
    public void ConstructorRejectsEmptyPassword()
    {
        Assert.Throws<ArgumentException>(() =>
            new FileCertificatePersistenceStrategy(_root, string.Empty));
    }

    [Fact]
    public void ConstructorRejectsNullPassword()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new FileCertificatePersistenceStrategy(_root, null!));
    }

    // ── Key file is not plaintext ──────────────────────────────────────────────────

    [Fact]
    public async Task PrivateKeyFileIsEncryptedWhenUsingPersistSiteCertificate()
    {
        var cert = MakeCert();
        await _strategy.PersistSiteCertificate(cert, "route.alpha");

        var keyPath = Path.Combine(_root, "route.alpha", "keys", "server.key");
        Assert.True(File.Exists(keyPath));

        var keyContent = await File.ReadAllTextAsync(keyPath, TestContext.Current.CancellationToken);

        Assert.DoesNotContain("BEGIN EC PRIVATE KEY", keyContent, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN RSA PRIVATE KEY", keyContent, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", keyContent, StringComparison.Ordinal);
        Assert.Contains("BEGIN ENCRYPTED PRIVATE KEY", keyContent, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PrivateKeyFileIsEncryptedWhenUsingPersistSiteCertificateChain()
    {
        var cert = MakeCert();
        var chain = new X509Certificate2Collection { cert };
        await _strategy.PersistSiteCertificateChain(chain, "route.alpha");

        var keyPath = Path.Combine(_root, "route.alpha", "keys", "server.key");
        Assert.True(File.Exists(keyPath));

        var keyContent = await File.ReadAllTextAsync(keyPath, TestContext.Current.CancellationToken);

        Assert.DoesNotContain("BEGIN EC PRIVATE KEY", keyContent, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN RSA PRIVATE KEY", keyContent, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN PRIVATE KEY", keyContent, StringComparison.Ordinal);
        Assert.Contains("BEGIN ENCRYPTED PRIVATE KEY", keyContent, StringComparison.Ordinal);
    }

    // ── PFX is password-protected ─────────────────────────────────────────────────

    [Fact]
    public async Task PfxCannotBeLoadedWithWrongPassword()
    {
        var cert = MakeCert();
        await _strategy.PersistSiteCertificate(cert, "route.alpha");

        var pfxPath = Path.Combine(_root, "route.alpha", "leaves", "server.pfx");
        Assert.True(File.Exists(pfxPath));

        var pfxBytes = await File.ReadAllBytesAsync(pfxPath, TestContext.Current.CancellationToken);
        Assert.Throws<CryptographicException>(() =>
            X509CertificateLoader.LoadPkcs12(pfxBytes, "wrong-password"));
    }

    [Fact]
    public async Task PfxCanBeLoadedWithCorrectPassword()
    {
        var cert = MakeCert();
        await _strategy.PersistSiteCertificate(cert, "route.alpha");

        var pfxPath = Path.Combine(_root, "route.alpha", "leaves", "server.pfx");
        var pfxBytes = await File.ReadAllBytesAsync(pfxPath, TestContext.Current.CancellationToken);

        var loaded = X509CertificateLoader.LoadPkcs12(pfxBytes, TestPassword);
        Assert.Equal(cert.Thumbprint, loaded.Thumbprint);
    }

    // ── Round-trip: persist → retrieve ────────────────────────────────────────────

    [Fact]
    public async Task RetrieveSiteCertificateReturnsOriginalCertViaChainOverload()
    {
        var cert = MakeCert();
        var chain = new X509Certificate2Collection { cert };
        await _strategy.PersistSiteCertificateChain(chain, "route.alpha");

        var retrieved = await _strategy.RetrieveSiteCertificate("route.alpha");

        Assert.NotNull(retrieved);
        Assert.Equal(cert.Thumbprint, retrieved.Thumbprint);
        Assert.True(retrieved.HasPrivateKey);
    }

    [Fact]
    public async Task RetrieveSiteCertificateReturnsOriginalCertViaSingleOverload()
    {
        var cert = MakeCert();
        await _strategy.PersistSiteCertificate(cert, "route.alpha");

        var retrieved = await _strategy.RetrieveSiteCertificate("route.alpha");

        Assert.NotNull(retrieved);
        Assert.Equal(cert.Thumbprint, retrieved.Thumbprint);
        Assert.True(retrieved.HasPrivateKey);
    }

    // ── Route key round-trip ──────────────────────────────────────────────────────

    [Fact]
    public async Task PersistRouteKeyStoresEncryptedAndGetPersistedRouteKeyReturnsDecryptedPem()
    {
        var cert = MakeCert();
        using var ecdsa = cert.GetECDsaPrivateKey()!;
        var plainKeyPem = ecdsa.ExportECPrivateKeyPem();

        await _strategy.PersistRouteKey("route.alpha", plainKeyPem, TestContext.Current.CancellationToken);

        var keyPath = Path.Combine(_root, "route.alpha", "keys", "server.key");
        var storedContent = await File.ReadAllTextAsync(keyPath, TestContext.Current.CancellationToken);

        // Stored content must be encrypted
        Assert.Contains("BEGIN ENCRYPTED PRIVATE KEY", storedContent, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN EC PRIVATE KEY", storedContent, StringComparison.Ordinal);

        var retrieved = await _strategy.GetPersistedRouteKey("route.alpha", TestContext.Current.CancellationToken);
        Assert.NotNull(retrieved);

        // Retrieved PEM is plaintext and usable by KeyFactory.FromPem
        Assert.DoesNotContain("ENCRYPTED", retrieved, StringComparison.Ordinal);
        Assert.Contains("PRIVATE KEY", retrieved, StringComparison.Ordinal);

        // Verify the decrypted key matches the original
        using var restored = ECDsa.Create();
        restored.ImportFromPem(retrieved);
        var originalQ = ecdsa.ExportParameters(false).Q;
        var restoredQ = restored.ExportParameters(false).Q;
        Assert.Equal(originalQ.X, restoredQ.X);
        Assert.Equal(originalQ.Y, restoredQ.Y);
    }

    [Fact]
    public async Task PersistRouteKeyRoundTripsRsaKeys()
    {
        var cert = MakeRsaCert();
        using var rsa = cert.GetRSAPrivateKey()!;
        var plainKeyPem = rsa.ExportRSAPrivateKeyPem();

        await _strategy.PersistRouteKey("route.rsa", plainKeyPem, TestContext.Current.CancellationToken);

        var keyPath = Path.Combine(_root, "route.rsa", "keys", "server.key");
        var storedContent = await File.ReadAllTextAsync(keyPath, TestContext.Current.CancellationToken);

        Assert.Contains("BEGIN ENCRYPTED PRIVATE KEY", storedContent, StringComparison.Ordinal);
        Assert.Contains("KEYTYPE:RSA", storedContent, StringComparison.Ordinal);
        Assert.DoesNotContain("BEGIN RSA PRIVATE KEY", storedContent, StringComparison.Ordinal);

        var retrieved = await _strategy.GetPersistedRouteKey("route.rsa", TestContext.Current.CancellationToken);
        Assert.NotNull(retrieved);
        Assert.DoesNotContain("ENCRYPTED", retrieved, StringComparison.Ordinal);
        Assert.Contains("BEGIN RSA PRIVATE KEY", retrieved, StringComparison.Ordinal);

        using var restored = RSA.Create();
        restored.ImportFromPem(retrieved);
        Assert.Equal(rsa.ExportParameters(true).Modulus, restored.ExportParameters(true).Modulus);
        Assert.Equal(rsa.ExportParameters(true).Exponent, restored.ExportParameters(true).Exponent);
    }

    [Fact]
    public async Task GetPersistedRouteKeyReturnsNullWhenNoKeyPersisted()
    {
        var result = await _strategy.GetPersistedRouteKey("nonexistent-route", TestContext.Current.CancellationToken);
        Assert.Null(result);
    }
}
