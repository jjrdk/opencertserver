namespace OpenCertServer.Acme.AspNetClient.Persistence;

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using OpenCertServer.Acme.Abstractions.Acme;

internal sealed class InMemoryCertificatePersistenceStrategy : ICertificatePersistenceStrategy
{
    private byte[]? _accountCertificate;
    private byte[]? _siteCertificate;
    private readonly Dictionary<string, byte[]> _routeSiteCertificates = new();

    public Task Persist(CertificateType persistenceType, byte[] certificate)
      {
          switch (persistenceType)
             {
              case CertificateType.Account:
                  _accountCertificate = certificate;
                  break;
              case CertificateType.Site:
                  _siteCertificate = certificate;
                  break;
              default:
                  throw new ArgumentException("Unhandled persistence type", nameof(persistenceType));
             }

          return Task.CompletedTask;
      }

    public Task PersistSiteCertificate(X509Certificate2 certificate)
      {
          _routeSiteCertificates[AcmeRouteConstants.DefaultRouteId] = certificate.RawData;
          _siteCertificate = certificate.RawData;
          return Task.CompletedTask;
      }

    public Task PersistSiteCertificate(X509Certificate2 certificate, string routeId)
      {
          var key = NormalizeRouteId(routeId);
          _routeSiteCertificates[key] = certificate.RawData;
          if (key == AcmeRouteConstants.DefaultRouteId)
           {
            _siteCertificate = certificate.RawData;
           }

          return Task.CompletedTask;
      }

    public Task<byte[]?> RetrieveAccountCertificate()
      {
          return Task.FromResult(_accountCertificate);
      }

    public Task<X509Certificate2?> RetrieveSiteCertificate()
      {
          return Task.FromResult(_siteCertificate == null
               ? null
              : X509CertificateLoader.LoadCertificate(_siteCertificate));
      }

    public Task<X509Certificate2?> RetrieveSiteCertificate(string routeId)
      {
          var key = NormalizeRouteId(routeId);
          var bytes = _routeSiteCertificates.TryGetValue(key, out var stored)
                ? stored
               : key == AcmeRouteConstants.DefaultRouteId
                 ? _siteCertificate
                 : null;

          return Task.FromResult(bytes == null
               ? null
              : X509CertificateLoader.LoadCertificate(bytes));
      }

      private static string NormalizeRouteId(string? routeId)
      {
          var id = routeId ?? AcmeRouteConstants.DefaultRouteId;
          return string.Equals(id, AcmeRouteConstants.DefaultRouteId, StringComparison.Ordinal)
                ? AcmeRouteConstants.DefaultRouteId
             : id;
      }
}
