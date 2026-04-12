namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Persistence;
using Xunit;

/// <summary>
/// Integration tests for <see cref="CertificateStorePersistenceStrategy"/>.
/// </summary>
/// <remarks>
/// <para>
/// Each test method gets its own instance of this class (xUnit default), and therefore its own
/// unique <c>_subjectName</c> GUID.  This guarantees that concurrent or sequential test runs
/// never share OS-store entries.
/// </para>
/// <para>
/// <see cref="IAsyncLifetime"/> is used so that <see cref="InitializeAsync"/> (before) and
/// <see cref="DisposeAsync"/> (after) both purge any store entries carrying the test subject
/// name.  The before-step is a defensive measure in case a prior test run crashed before
/// <see cref="DisposeAsync"/> could execute.
/// </para>
/// </remarks>
public sealed class CertificateStorePersistenceTests : IAsyncLifetime
{
    // Each xUnit test method creates a new class instance, so this GUID is unique per test.
    private readonly string _subjectName = $"acme-test-{Guid.NewGuid():N}";
    private ICertificatePersistenceStrategy Strategy { get; }

    public CertificateStorePersistenceTests()
    {
        Strategy = new CertificateStorePersistenceStrategy(_subjectName);
    }

    /// <summary>
    /// Runs BEFORE the test body.  Removes any store entries that may have been left behind by
    /// a previous run that did not reach <see cref="DisposeAsync"/> (e.g. process crash).
    /// </summary>
    public ValueTask InitializeAsync()
    {
        PurgeTestCertificatesFromStore();
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Runs AFTER the test body (including on failure).  Guarantees that every certificate
    /// added during the test is removed from the OS store.
    /// </summary>
    public ValueTask DisposeAsync()
    {
        PurgeTestCertificatesFromStore();
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Removes all certificates whose Subject contains <c>_subjectName</c> from the personal
    /// store.  Silently ignores errors so cleanup never causes a test to fail.
    /// </summary>
    private void PurgeTestCertificatesFromStore()
    {
        try
        {
            using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            var toRemove = store.Certificates
                .Find(X509FindType.FindBySubjectName, _subjectName, validOnly: false);

            foreach (var cert in toRemove)
            {
                store.Remove(cert);
            }
        }
        catch
        {
            // Best-effort – never let cleanup throw and shadow the real test failure.
        }
    }

    [Fact]
    public async Task MissingAccountCertificateReturnsNull()
    {
        var result = await Strategy.RetrieveAccountCertificate();
        Assert.Null(result);
    }

    [Fact]
    public async Task MissingSiteCertificateReturnsNull()
    {
        var result = await Strategy.RetrieveSiteCertificate();
        Assert.Null(result);
    }

    [Fact]
    public async Task AccountCertificateIsNotStoredInOsStore()
    {
        // The strategy must not store account (ACME private key) material in the OS cert store.
        var someBytes = new byte[] { 1, 2, 3, 4 };
        await Strategy.Persist(CertificateType.Account, someBytes);

        var result = await Strategy.RetrieveAccountCertificate();
        Assert.Null(result);
    }

    [Fact]
    public async Task SiteCertificateRoundTripWithPrivateKey()
    {
        // PersistSiteCertificate stores the full cert (incl. private key) in the OS store.
        var original = SelfSignedCertificate.MakeWithSubject(
            _subjectName,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(90));

        Assert.True(original.HasPrivateKey, "Test cert must have a private key");

        await Strategy.PersistSiteCertificate(original);

        var retrieved = await Strategy.RetrieveSiteCertificate();

        Assert.NotNull(retrieved);
        Assert.Equal(original.Thumbprint, retrieved.Thumbprint);
        Assert.True(retrieved.HasPrivateKey, "Retrieved cert must retain its private key");
    }

    [Fact]
    public async Task SiteCertificateStoredViaBytesInterfaceIsNotRetrievable()
    {
        // Persist(CertificateType.Site, bytes) is the legacy DER-bytes path and does NOT include
        // a private key.  CertificateStorePersistenceStrategy only returns certificates that have
        // an accessible private key (via HasPrivateKey), so a cert stored this way will not be
        // found by RetrieveSiteCertificate.
        // Callers should use PersistSiteCertificate(X509Certificate2) to store the full cert.
        var original = SelfSignedCertificate.MakeWithSubject(
            _subjectName,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(90));

        await Strategy.Persist(CertificateType.Site, original.RawData);

        var retrieved = await Strategy.RetrieveSiteCertificate();

        // Null is expected: the DER bytes stored no private key, so HasPrivateKey is false and
        // the entry is not returned.
        Assert.Null(retrieved);
    }

    [Fact]
    public async Task PersistingNewCertificateRemovesOldOne()
    {
        var first = SelfSignedCertificate.MakeWithSubject(
            _subjectName,
            DateTimeOffset.UtcNow.AddDays(-2),
            DateTimeOffset.UtcNow.AddDays(30));

        var second = SelfSignedCertificate.MakeWithSubject(
            _subjectName,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(90));

        await Strategy.PersistSiteCertificate(first);
        await Strategy.PersistSiteCertificate(second);

        // Only the newest cert should remain in the store.
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        var matches = store.Certificates
            .Find(X509FindType.FindBySubjectName, _subjectName, validOnly: false);

        Assert.Single(matches);
        Assert.Equal(second.Thumbprint, matches[0].Thumbprint);
    }

    [Fact]
    public async Task MostRecentCertificateIsReturnedWhenMultipleExist()
    {
        // Add two certs directly (bypassing subject-cleanup logic) to simulate
        // an unusual scenario where duplicates exist.
        var older = SelfSignedCertificate.MakeWithSubject(
            _subjectName,
            DateTimeOffset.UtcNow.AddDays(-2),
            DateTimeOffset.UtcNow.AddDays(30));

        var newer = SelfSignedCertificate.MakeWithSubject(
            _subjectName,
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(90));

        using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
        {
            store.Open(OpenFlags.ReadWrite);
            store.Add(older);
            store.Add(newer);
        }

        var retrieved = await Strategy.RetrieveSiteCertificate();

        Assert.NotNull(retrieved);
        Assert.Equal(newer.Thumbprint, retrieved.Thumbprint);
    }
}


