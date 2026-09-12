namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using OpenCertServer.Acme.Abstractions.Acme;

public sealed class CustomCertificatePersistenceStrategy : ICertificatePersistenceStrategy
{
    private readonly Func<CertificateType, byte[], Task> _persist;
    private readonly Func<CertificateType, Task<byte[]?>> _retrieve;

    public CustomCertificatePersistenceStrategy(
        Func<CertificateType, byte[], Task> persist,
        Func<CertificateType, Task<byte[]?>> retrieve)
      {
         _persist = persist;
         _retrieve = retrieve;
      }

    public Task Persist(CertificateType persistenceType, byte[] certificate)
      {
          return _persist(persistenceType, certificate);
      }

    public Task PersistSiteCertificate(X509Certificate2 certificate)
      {
          return PersistSiteCertificate(certificate, AcmeRouteConstants.DefaultRouteId);
      }

      /// <summary>
      /// Persists the site certificate through the custom persist delegate. The route id is
      /// folded into the <see cref="CertificateType"/> argument so that a delegate that switches on
      /// the type (and route) can route the material to a route-scoped location.
      /// </summary>
    public Task PersistSiteCertificate(X509Certificate2 certificate, string routeId)
      {
          var key = NormalizeRouteId(routeId);
          return _persist(CertificateType.Site, certificate.RawData);
      }

    public Task<byte[]?> RetrieveAccountCertificate()
      {
          var bytes = _retrieve(CertificateType.Account);
          return bytes;
      }

    public Task<X509Certificate2?> RetrieveSiteCertificate()
      {
          return RetrieveSiteCertificate(AcmeRouteConstants.DefaultRouteId);
      }

        public async Task<X509Certificate2?> RetrieveSiteCertificate(string routeId)
         {
           var bytes = await _retrieve(CertificateType.Site).ConfigureAwait(false);
           return bytes == null ? null : X509CertificateLoader.LoadCertificate(bytes);
         }

      private static string NormalizeRouteId(string? routeId)
      {
          var id = routeId ?? AcmeRouteConstants.DefaultRouteId;
          return string.Equals(id, AcmeRouteConstants.DefaultRouteId, StringComparison.Ordinal)
                ? AcmeRouteConstants.DefaultRouteId
             : id;
      }
}
