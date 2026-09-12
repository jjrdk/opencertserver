namespace OpenCertServer.Acme.Yarp.Tests;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Acme.Abstractions.Acme;
using Acme.AspNetClient.Certificates;
using Acme.AspNetClient.Persistence;

/// <summary>
/// A concrete <see cref="IProvideCertificates"/> that drives the renewal engine per route through a
/// caller-supplied handler, so the per-route behaviour can be exercised without a live ACME server.
/// When a route's handler throws, the failure is surfaced to the renewal service exactly as a real
/// network failure would be.
/// </summary>
internal sealed class RoutingCertificateProvider : IProvideCertificates
{
     private readonly Func<string, CancellationToken, Task<X509Certificate2?>> _renew;

     public RoutingCertificateProvider(
        Func<string, CancellationToken, Task<X509Certificate2?>> renew)
           {
         _renew = renew;
            }

     public Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        CancellationToken cancellationToken = default)
           => Renew(password, null, Array.Empty<string>(), cancellationToken);

     public Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        X509Certificate2? current,
        CancellationToken cancellationToken = default)
           => Renew(password, null, Array.Empty<string>(), cancellationToken);

     public Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        string? routeId,
        X509Certificate2? current = null,
        CancellationToken cancellationToken = default)
           => Renew(password, routeId, Array.Empty<string>(), cancellationToken);

     public Task<CertificateRenewalResult> RenewCertificateIfNeeded(
        string password,
        string? routeId,
        IReadOnlyList<string> hosts,
        X509Certificate2? current = null,
        CancellationToken cancellationToken = default)
           => Renew(password, routeId, hosts, cancellationToken);

     private async Task<CertificateRenewalResult> Renew(
        string password,
        string? routeId,
        IReadOnlyList<string> hosts,
        CancellationToken cancellationToken)
           {
          var cert = await _renew(routeId ?? AcmeRouteConstants.DefaultRouteId, cancellationToken)
               .ConfigureAwait(false);

          var status = cert == null
               ? CertificateRenewalStatus.Unchanged
              : CertificateRenewalStatus.Renewed;

          return new CertificateRenewalResult(cert, status);
            }
}
