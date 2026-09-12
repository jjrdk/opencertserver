namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Persistence;
using Xunit;

/// <summary>
/// Covers §4.2 for the OS certificate store strategy: each route is stored under its own
/// subject (<c>{subjectName}@{routeId}</c>) so that distinct routes never collide in the store,
/// while the default route keeps the bare subject.
/// </summary>
public sealed class CertificateStorePersistenceRouteScopedTests : IAsyncLifetime
{
    private readonly string _subjectName = $"acme-route-test-{Guid.NewGuid():N}";
    private readonly CertificateStorePersistenceStrategy _strategy;

    public CertificateStorePersistenceRouteScopedTests()
        {
          _strategy = new CertificateStorePersistenceStrategy(_subjectName, StoreName.CertificateAuthority, StoreLocation.CurrentUser);
      }

    public ValueTask InitializeAsync()
      {
      Purge();
      return ValueTask.CompletedTask;
      }

    public ValueTask DisposeAsync()
      {
      Purge();
      return ValueTask.CompletedTask;
      }

      private void Purge()
         {
        try
             {
            using var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            foreach (var subject in new[] { _subjectName, $"{_subjectName}@route.alpha", $"{_subjectName}@route.beta" })
                 {
                 var matches = store.Certificates.Find(X509FindType.FindBySubjectName, subject, validOnly: false);
                 foreach (var old in matches)
                     {
                     store.Remove(old);
                       }
                 }
           }
        catch
           {
           }
         }

    [Fact]
    public async Task DistinctRoutesAreStoredAndRetrievedIndependently()
       {
      Assert.Null(await _strategy.RetrieveSiteCertificate("route.alpha"));
      Assert.Null(await _strategy.RetrieveSiteCertificate("route.beta"));

      var alpha = SelfSignedCertificate.MakeWithSubject(
           $"{_subjectName}@route.alpha", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));
      var beta = SelfSignedCertificate.MakeWithSubject(
           $"{_subjectName}@route.beta", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(91));

      await _strategy.PersistSiteCertificate(alpha, "route.alpha");
      await _strategy.PersistSiteCertificate(beta, "route.beta");

      var backAlpha = await _strategy.RetrieveSiteCertificate("route.alpha");
      var backBeta = await _strategy.RetrieveSiteCertificate("route.beta");

      Assert.Equal(alpha.Thumbprint, backAlpha!.Thumbprint);
      Assert.Equal(beta.Thumbprint, backBeta!.Thumbprint);
      Assert.NotEqual(backAlpha.Thumbprint, backBeta.Thumbprint);
       }

    [Fact]
    public async Task RenewingARouteDoesNotAccumulateStoreEntries()
       {
      var older = SelfSignedCertificate.MakeWithSubject(
           $"{_subjectName}@route.alpha", DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(30));
      var newer = SelfSignedCertificate.MakeWithSubject(
           $"{_subjectName}@route.alpha", DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));

      await _strategy.PersistSiteCertificate(older, "route.alpha");
      await _strategy.PersistSiteCertificate(newer, "route.alpha");

      using var store = new X509Store(StoreName.CertificateAuthority, StoreLocation.CurrentUser);
      store.Open(OpenFlags.ReadOnly);
      var matches = store.Certificates.Find(X509FindType.FindBySubjectName, $"{_subjectName}@route.alpha", validOnly: false);

      Assert.Single(matches);

      var retrieved = await _strategy.RetrieveSiteCertificate("route.alpha");
      Assert.Equal(newer.Thumbprint, retrieved!.Thumbprint);
       }

    [Fact]
    public async Task DefaultRouteUsesBareSubject()
    {
      var cert = SelfSignedCertificate.MakeWithSubject(
           _subjectName, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(90));

      await _strategy.PersistSiteCertificate(cert);

      var retrieved = await _strategy.RetrieveSiteCertificate();
      Assert.Equal(cert.Thumbprint, retrieved!.Thumbprint);
    }
}
