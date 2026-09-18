# opencertserver.acme.yarp

ACME-per-route support for **YARP (`Yarp.ReverseProxy`**). This library lets a single YARP reverse
proxy provision, renew and serve **one ACME (X509) certificate per route**, selected by SNI, with
each certificate stored in a route-scoped location.

## How it works

- **Per-route descriptor.** Each YARP `RouteConfig` that carries an `acme` metadata bag (via
  `RouteAcmeMetadataExtensions.WithAcmeRoute`) becomes an independent `IAcmeRouteConfiguration`
  (`RouteId`, `Hosts` → SANs, optional `CommonName`/CSR override), published to a
  `IAcmeRouteConfigurationSource`.
- **Route-scoped storage.** The existing `IPersistenceService` is extended with a route id. Each
  route's leaf/chain/key live under a route-scoped directory
  (`{root}/{routeId}/leaves|chains|keys`), so multiple TLS certificates coexist on one HTTPS
  listener.
- **SNI selection.** `KestrelOptionsSetup` builds a `host → routeId` index from the route source and
  serves the matching route's renewed leaf for each SNI host; an unmatched host falls back to the
  `__default__` leaf and logs a warning. Renewals are picked up on the next handshake without a
  restart.
- **HTTP-01.** The existing `AcmeChallengeApprovalMiddleware` serves challenge tokens for every
  route unchanged (the token is globally unique and host-agnostic).
- **Renewal.** The existing `AcmeRenewalService` iterates the route source on each tick; a failure
  on one route does not block the others.

## Usage

A web server that provisions two certificates (one per YARP route) on a single HTTPS listener:

```csharp
using System.Collections.Generic;
using CertesSlim.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Acme.AspNetClient;
using OpenCertServer.Acme.AspNetClient.Certes;
using OpenCertServer.Acme.Yarp;
using Yarp.ReverseProxy.Configuration;

// 1. Point the ACME engine at the server you trust (Let's Encrypt or a Pebble test server) and
//    configure the CSR metadata shared by every route. Each route's Match.Hosts become the SANs,
//    so Domains can be empty for a YARP-only deployment.
var options = new LetsEncryptOptions
{
   Email = "you@example.com",
   UseStaging = false,                       // set true to hit the Let's Encrypt staging server
   AccountPassword = "change-me",
   TimeUntilExpiryBeforeRenewal = TimeSpan.FromDays(30),
   CertificateSigningRequest = new CsrInfo
     {
       CountryName = "US",
       Organization = "Example Corp",
       State = "CA",
       Locality = "San Francisco"
     }
};

var builder = WebApplication.CreateBuilder(args);

// 2. The ACME client factory needs an HttpClient, so register one before the client wiring.
builder.Services.AddHttpClient();

// 3. Persist each route's leaf/chain/key under a route-scoped directory
//    (e.g. acme-certificates/<routeId>), and challenges likewise.
builder.Services.AddAcmeClient(options)
     .AddAcmeFileCertificatePersistence("acme-certificates")
     .AddAcmeFileChallengePersistence("acme-challenges");

// 4. Declare the YARP routes. Each RouteConfig that carries an `acme` metadata bag (via
//    WithAcmeRoute) becomes an independent ACME order; its Match.Hosts become the certificate
//    SANs. The ACME options are attached to the RouteConfig in code with WithAcmeRoute — they are
//    NOT read from an "AcmeProxy" section of appsettings.json.
var routes = new List<RouteConfig>
{
   RouteAcmeMetadataExtensions.WithAcmeRoute(
      new RouteConfig
        {
          RouteId = "route.alpha",
          ClusterId = "cluster.alpha",
          Match = new RouteMatch { Hosts = ["alpha.example.com"] }
        },
      new RouteAcmeOptions { CommonName = "alpha.example.com" }),
   RouteAcmeMetadataExtensions.WithAcmeRoute(
      new RouteConfig
        {
          RouteId = "route.beta",
          ClusterId = "cluster.beta",
          Match = new RouteMatch { Hosts = ["beta.example.com"] }
        },
      new RouteAcmeOptions { CommonName = "beta.example.com" })
};

// ClusterConfig.Destinations is an IReadOnlyDictionary, so assign an initialized
// Dictionary, and DestinationConfig has a parameterless constructor.
var clusters = new List<ClusterConfig>
{
   new()
     {
       ClusterId = "cluster.alpha",
       Destinations = new Dictionary<string, DestinationConfig>
         {
           { "alpha", new DestinationConfig { Address = "http://localhost:5001" } }
         }
     },
   new()
     {
       ClusterId = "cluster.beta",
       Destinations = new Dictionary<string, DestinationConfig>
         {
           { "beta", new DestinationConfig { Address = "http://localhost:5002" } }
         }
     }
};

// 5. Register the route registry (exposed as IAcmeRouteConfigurationSource) and load the routes and
//    clusters. WithAcmeRouteFilter attaches the config-filter that discovers the `acme` metadata
//    bag on each route and registers a renewal descriptor; LoadFromMemory runs that filter. Call
//    AddAcmeProxy after AddAcmeClient so the renewal engine is present.
builder.Services.AddAcmeProxy()
     .WithAcmeRouteFilter()
     .LoadFromMemory(routes, clusters);

// 6. Kestrel serves the per-route leaf by SNI; TLS 1.2/1.3 for the HTTPS listener.
builder.WebHost.UseKestrel(kestrel =>
{
   kestrel.ConfigureHttpsDefaults(https =>
   {
     https.SslProtocols = System.Security.Authentication.SslProtocols.Tls12
        | System.Security.Authentication.SslProtocols.Tls13;
   });
});

var app = builder.Build();

// 7. The ACME challenge middleware serves HTTP-01 tokens for every route; YARP forwards the rest.
//    In YARP 2.x the proxy is registered as an endpoint with MapReverseProxy, not UseReverseProxy.
app.UseAcmeClient();
app.MapReverseProxy();
app.Run();
```

On start, `AcmeRenewalService.StartAsync` calls `RunAllRoutesOnce`, which requests a new
certificate from Let's Encrypt for every registered route (one per `RouteConfig`); each route's
leaf is then selected by SNI on the single HTTPS listener.

### Configuration via `appsettings.json`

The YARP routes/clusters can also be declared in `appsettings.json` instead of code. The ACME
metadata is **not** read from `appsettings.json`; an `acme` metadata bag must still be attached to
each `RouteConfig` in code with `WithAcmeRoute`. A routing section that mirrors the routes above:

```json
{
   "ReverseProxy": {
      "Routes": {
         "route.alpha": { "ClusterId": "cluster.alpha", "Match": { "Hosts": [ "alpha.example.com" ] } },
         "route.beta":  { "ClusterId": "cluster.beta",  "Match": { "Hosts": [ "beta.example.com" ] } }
      },
      "Clusters": {
         "cluster.alpha": { "Destinations": { "alpha": { "Address": "http://localhost:5001" } } },
         "cluster.beta":  { "Destinations": { "beta":  { "Address": "http://localhost:5002" } } }
      }
   }
}
```

See `sample/Program.cs` and `sample/appsettings.json` for a complete, illustrative program, and the
root `README.md` "Using ACME with YARP" section.

## Backward compatibility

When no route is ACME-tagged, the renewal engine and Kestrel selector fall back to the
`__default__` route, preserving the legacy single-listener `UseAcmeClient()` behaviour.

## Known limitations

- **No runtime route removal (v1).** `AcmeRouteConfigurationRegistry.AddConfiguration` only adds or
  updates descriptors. If a YARP route is removed via hot-config-reload, its ACME descriptor remains
  registered until the process restarts, and the renewal service and SNI selector keep servicing it.
  Runtime removal is tracked as a future enhancement and will be wired to the YARP
  `IProxyConfigProvider` change token when hot-reload is implemented.

## Tests

See `tests/opencertserver.acme.yarp.tests` (registration §4.1, SNI selection §4.3, renewal lifecycle
§4.4, HTTP-01 challenge §4.5, backward compatibility §4.6) and
`tests/opencertserver.acme.aspnetclient.tests` (route-scoped persistence §4.2).
