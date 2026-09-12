// Sample program: provision two ACME certificates for two YARP routes on a single HTTPS listener,
// each stored route-scoped and selected by SNI via the ACME per-route plumbing.
//
// This file documents the intended wiring. It is illustrative and is not part of a compiled
// project in the solution; see the accompanying appsettings.json and the README "Using ACME with
// YARP" section.
using System.Collections.Generic;
using CertesSlim.Extensions;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Acme.AspNetClient.Certes;
using OpenCertServer.Acme.Yarp;
using Yarp.ReverseProxy.Configuration;

// 1. Point the ACME engine at the server you trust (Pebble/Let's Encrypt) and configure the CSR
//    metadata shared by every route.
var options = new LetsEncryptOptions
{
    Email = "you@example.com",
    // UseStaging = true,
    AccountPassword = "change-me",
    Domains = ["alpha.example.com", "beta.example.com"],
    TimeUntilExpiryBeforeRenewal = System.TimeSpan.FromDays(30),
    CertificateSigningRequest = new CsrInfo
     {
        CountryName = "US",
        Organization = "Example Corp",
        State = "CA",
        Locality = "San Francisco"
     }
};

var builder = WebApplication.CreateBuilder(args);

// 2. Persist each route's leaf/chain/key under a route-scoped directory (e.g. acme-certificates/<routeId>).
builder.Services.AddAcmeClient(options)
      .AddAcmeFileCertificatePersistence("acme-certificates")
      .AddAcmeFileChallengePersistence("acme-challenges")
;

// 3. Declare the YARP routes. Each route that carries an `acme` metadata bag is registered as an
//    independent ACME order; its Match.Hosts become the certificate SANs.
var alpha = RouteAcmeMetadataExtensions.WithAcmeRoute(
    new RouteConfig
     {
        RouteId = "route.alpha",
        ClusterId = "cluster.alpha",
        Match = new RouteMatch { Hosts = ["alpha.example.com"] }
     },
    new RouteAcmeOptions { CommonName = "alpha.example.com" });

var beta = RouteAcmeMetadataExtensions.WithAcmeRoute(
    new RouteConfig
     {
        RouteId = "route.beta",
        ClusterId = "cluster.beta",
        Match = new RouteMatch { Hosts = ["beta.example.com"] }
     },
    new RouteAcmeOptions { CommonName = "beta.example.com" });

var routes = new List<RouteConfig> { alpha, beta };
var clusters = new List<ClusterConfig>
{
    new() { ClusterId = "cluster.alpha", Destinations = { { "alpha", new DestinationConfig("http://localhost:5001") } } },
    new() { ClusterId = "cluster.beta", Destinations = { { "beta", new DestinationConfig("http://localhost:5002") } } }
};

// 4. Wire the ACME route config filter into YARP and load the routes/clusters. `AddAcmeProxy`
//    registers the route registry (exposed as IAcmeRouteConfigurationSource) that the renewal
//    service and Kestrel SNI selector read; `UseAcmeProxy` attaches the config filter that
//    discovers the `acme` metadata bag on each route; `LoadFromMemory` loads the config, running
//    the filter and registering each ACME route as a renewal descriptor.
builder.Services.AddAcmeProxy()
      .UseAcmeProxy()
      .LoadFromMemory(routes, clusters);

var app = builder.Build();

// 5. The ACME challenge middleware serves HTTP-01 tokens for any route; YARP forwards the rest.
app.UseAcmeClient();
app.UseReverseProxy();

// 6. Kestrel selects the per-route leaf by SNI; an unmatched SNI host falls back to the default
//    route leaf. Renewals are picked up on the next handshake without restarting the listener.
app.Run();
