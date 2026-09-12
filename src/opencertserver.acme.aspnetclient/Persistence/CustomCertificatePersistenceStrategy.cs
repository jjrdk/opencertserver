namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using OpenCertServer.Acme.Abstractions.Acme;

public sealed class CustomCertificatePersistenceStrategy : ICertificatePersistenceStrategy
{
    private readonly Func<CertificateType, byte[], Task> _persist;
    private readonly Func<CertificateType, Task<byte[]?>> _retrieve;
    private readonly Func<string, CertificateType, byte[], Task>? _persistWithRoute;
    private readonly Func<string, CertificateType, Task<byte[]?>>? _retrieveWithRoute;

    public CustomCertificatePersistenceStrategy(
        Func<CertificateType, byte[], Task> persist,
        Func<CertificateType, Task<byte[]?>> retrieve)
      {
         _persist = persist;
         _retrieve = retrieve;
      }

    /// <summary>
    /// Initializes a new instance that supports per-route storage via route-aware delegates.
    /// </summary>
    public CustomCertificatePersistenceStrategy(
        Func<CertificateType, byte[], Task> persist,
        Func<CertificateType, Task<byte[]?>> retrieve,
        Func<string, CertificateType, byte[], Task> persistWithRoute,
        Func<string, CertificateType, Task<byte[]?>> retrieveWithRoute)
      {
         _persist = persist;
         _retrieve = retrieve;
         _persistWithRoute = persistWithRoute;
         _retrieveWithRoute = retrieveWithRoute;
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
      /// Persists the site certificate scoped to <paramref name="routeId"/>. When a route-aware
      /// persist delegate was supplied at construction time, it is invoked with the normalised route
      /// id; otherwise the call falls back to the non-scoped delegate.
      /// </summary>
    public Task PersistSiteCertificate(X509Certificate2 certificate, string routeId)
      {
          var key = NormalizeRouteId(routeId);
          return _persistWithRoute != null
              ? _persistWithRoute(key, CertificateType.Site, certificate.RawData)
              : _persist(CertificateType.Site, certificate.RawData);
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
          var key = NormalizeRouteId(routeId);
          var bytes = _retrieveWithRoute != null
              ? await _retrieveWithRoute(key, CertificateType.Site).ConfigureAwait(false)
              : await _retrieve(CertificateType.Site).ConfigureAwait(false);
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
