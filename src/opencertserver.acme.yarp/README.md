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

```csharp
builder.Services.AddAcmeClient(options)
   .AddAcmeFileCertificatePersistence("acme-certificates")
   .AddAcmeFileChallengePersistence("acme-challenges");

var routes = new List<RouteConfig>
{
   RouteAcmeMetadataExtensions.WithAcmeRoute(
      new RouteConfig { RouteId = "route.alpha", ClusterId = "cluster.alpha",
         Match = new RouteMatch { Hosts = ["alpha.example.com"] } },
      new RouteAcmeOptions { CommonName = "alpha.example.com" }),
   RouteAcmeMetadataExtensions.WithAcmeRoute(
      new RouteConfig { RouteId = "route.beta", ClusterId = "cluster.beta",
         Match = new RouteMatch { Hosts = ["beta.example.com"] } },
      new RouteAcmeOptions { CommonName = "beta.example.com" })
};

builder.Services.AddAcmeProxy().WithAcmeRouteFilter().LoadFromMemory(routes, clusters);

var app = builder.Build();
app.UseAcmeClient();       // HTTP-01 challenge middleware
app.UseReverseProxy();
app.Run();
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
