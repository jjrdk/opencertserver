namespace OpenCertServer.Acme.AspNetClient.Certes;

using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;
using OpenCertServer.Acme.Abstractions.Acme;

/// <summary>
/// Holds the per-route in-memory certificate state for the <see cref="AcmeRenewalService"/>.
/// </summary>
/// <remarks>
/// A single renewal service manages many routes at the same time. This container keeps a
/// route-scoped current leaf (<see cref="GetCertificate"/>/
/// <see cref="SetCertificate"/>) and a route-scoped leaf private key
/// (<see cref="GetKeyPem"/>/<see cref="SetKeyPem"/>) per route id. The private key is generated
/// once (on first issuance) and reused on subsequent renewals so that the ACME account key stays
/// global while the leaf key is route-scoped.
/// </remarks>
public sealed class AcmeRouteScope
{
    private readonly ConcurrentDictionary<string, X509Certificate2?> _certificates = new();
    private readonly ConcurrentDictionary<string, string> _keyPems = new();

public X509Certificate2? GetCertificate(string? routeId)
       {
         var key = routeId ?? AcmeRouteConstants.DefaultRouteId;
         return _certificates.TryGetValue(key, out var cert) ? cert : null;
       }

public X509Certificate2 GetCertificateOrElseThrow(string? routeId)
       {
         var key = routeId ?? AcmeRouteConstants.DefaultRouteId;
         return _certificates.TryGetValue(key, out var cert) && cert != null
               ? cert
               : throw new InvalidOperationException(
                    $"No certificate is available for route '{key}'. Renewal may not have completed yet.");
       }

public void SetCertificate(string? routeId, X509Certificate2? certificate)
       {
         var key = routeId ?? AcmeRouteConstants.DefaultRouteId;
         _certificates[key] = certificate;
       }

public string? GetKeyPem(string? routeId)
       {
         var key = routeId ?? AcmeRouteConstants.DefaultRouteId;
         return _keyPems.TryGetValue(key, out var pem) ? pem : null;
       }

public void SetKeyPem(string? routeId, string pem)
       {
         var key = routeId ?? AcmeRouteConstants.DefaultRouteId;
         _keyPems[key] = pem;
       }

public IEnumerable<IAcmeRouteConfiguration> GetRoutes(IAcmeRouteConfigurationSource source)
       {
         var routes = source.GetRouteConfigurations().ToList();
         if (routes.Count > 0)
           {
             return routes;
           }

         return [new RouteConfiguration(AcmeRouteConstants.DefaultRouteId, [])];
        }
}
