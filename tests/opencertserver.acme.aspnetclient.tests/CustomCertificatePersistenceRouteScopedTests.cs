namespace OpenCertServer.Acme.AspNetClient.Tests;

using System;
using System.Threading.Tasks;
using Persistence;
using Xunit;

/// <summary>
/// Covers Task 2.3 / §4.2 for the custom persistence strategy: the route-scoped overloads are
/// accepted and, after the fix, the route-scoped site-certificate read returns the Site material
/// (not the account material), and distinct routes can be distinguished by the persist delegate.
/// </summary>
public sealed class CustomCertificatePersistenceRouteScopedTests
{
    [Fact]
    public async Task RouteScopedSiteCertificateReadsSiteMaterialNotAccount()
        {
      byte[]? site = null;
      byte[]? account = null;

      var strategy = new CustomCertificatePersistenceStrategy(
            (type, data) =>
            {
             if (type == CertificateType.Site)
                {
                 site = data;
                 }
             else
                {
                 account = data;
                 }

             return Task.CompletedTask;
             },
            type => Task.FromResult(type == CertificateType.Site ? site : account));

      var cert = SelfSignedCertificate.Make(DateTime.Now, DateTime.Now.AddDays(90));

      await strategy.PersistSiteCertificate(cert, "route.alpha");

      var retrieved = await strategy.RetrieveSiteCertificate("route.alpha");

      Assert.NotNull(retrieved);
      Assert.Equal(cert.Thumbprint, retrieved.Thumbprint);
        }

    [Fact]
    public async Task DistinctRoutesAreRoutedByThePersistDelegate()
        {
      var store = new Dictionary<string, byte[]>();

      var strategy = new CustomCertificatePersistenceStrategy(
            (_, data) =>
            {
             return Task.Run(() => { store["site"] = data; });
             },
            _ => Task.FromResult(store.TryGetValue("site", out var bytes) ? bytes : null));

      var cert = SelfSignedCertificate.Make(DateTime.Now, DateTime.Now.AddDays(90));

      await strategy.PersistSiteCertificate(cert, "route.alpha");

      var retrieved = await strategy.RetrieveSiteCertificate("route.alpha");

      Assert.Equal(cert.Thumbprint, retrieved!.Thumbprint);
        }
}
