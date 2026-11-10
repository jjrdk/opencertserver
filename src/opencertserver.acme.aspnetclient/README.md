# opencertserver.acme.aspnetclient

The **ACME client for ASP.NET Core**. Registering it turns a `WebApplication`
into an ACME client: it provisions an ACME account, places orders, answers
`http-01` challenges through middleware, and auto-renews the site certificate
(SNI-selected) before it expires. Its root namespace is
`OpenCertServer.Acme.AspNetClient`
([opencertserver.acme.aspnetclient.csproj:5](opencertserver.acme.aspnetclient.csproj#L5)).

## What runs here

### Registration

[`RegistrationExtensions`](RegistrationExtensions.cs#L21) is the whole surface:

- **`AddAcmeClient(options)`** ([RegistrationExtensions.cs:237](RegistrationExtensions.cs#L237))
  and its DNS-provider overloads
  ([RegistrationExtensions.cs:206](RegistrationExtensions.cs#L206),
  [RegistrationExtensions.cs:223](RegistrationExtensions.cs#L223)) register the
  renewal service, client factory, persistence service, Kestrel setup and an
  `IAcmeRouteConfigurationSource`. The default `AddAcmeClient(options)` uses the
  no-op `NullDnsChallengeProvider`, so the `http-01` path is unaffected.
- **`UseAcmeClient()`** ([RegistrationExtensions.cs:262](RegistrationExtensions.cs#L262))
  registers the `AcmeChallengeApprovalMiddleware`.
- **Persistence extensions** — pick one certificate strategy and one challenge
  strategy:
  - `AddAcmeFileCertificatePersistence(password, …)`
    ([RegistrationExtensions.cs:105](RegistrationExtensions.cs#L105)) /
    `AddAcmeFileCertificatePersistence(path)`
    ([RegistrationExtensions.cs:119](RegistrationExtensions.cs#L119)) — file-backed,
    private key encrypted at rest (AES-256-CBC / PBKDF2-SHA256).
  - `AddAcmeCertificateStorePersistence(subjectName, …)`
    ([RegistrationExtensions.cs:160](RegistrationExtensions.cs#L160)) — the OS X.509
    store.
  - `AddAcmeInMemoryCertificatesPersistence()`
    ([RegistrationExtensions.cs:201](RegistrationExtensions.cs#L201)) — for tests.
  - `AddAcmeFileChallengePersistence(path)`
    ([RegistrationExtensions.cs:190](RegistrationExtensions.cs#L190)) /
    `AddAcmeMemoryChallengePersistence()`
    ([RegistrationExtensions.cs:196](RegistrationExtensions.cs#L196)).
  - Custom delegates via `AddAcmeCertificatePersistence` / `AddAcmeChallengePersistence`,
    and `AddAcmeRenewalLifecycleHook<T>`
    ([RegistrationExtensions.cs:40](RegistrationExtensions.cs#L40)).

### Options

- **`AcmeOptions`** ([Certes/AcmeOptions.cs:6](Certes/AcmeOptions.cs#L6)) — the
  abstract base: `AccountPassword` (required), `Domains`, `Email`,
  `TimeUntilExpiryBeforeRenewal` (default 30 days), `Profile`, and the
  `CertificateSigningRequest` (`CsrInfo`).
- **`LetsEncryptOptions`** ([Certes/LetsEncryptOptions.cs:6](Certes/LetsEncryptOptions.cs#L6)) —
  derives `AcmeServerUri` from `UseStaging` (`WellKnownServers.LetsEncryptV2` /
  `LetsEncryptStagingV2`).

### Client and renewal

- **`IAcmeClient` / `IAcmeClientFactory`** ([Certes/IAcmeClient.cs:6](Certes/IAcmeClient.cs#L6),
  [Certes/IAcmeClientFactory.cs:5](Certes/IAcmeClientFactory.cs#L5)) —
  `PlaceOrder(ChallengeType, domains)` and `FinalizeOrder(...)` (the concrete
  `AcmeClient` is built on [`CertesSlim`](../CertesSlim/README.md)).
- **`AcmeRenewalService`** ([Certes/AcmeRenewalService.cs:14](Certes/AcmeRenewalService.cs#L14))
  is an `IAcmeRenewalService : IHostedLifecycleService`
  ([Certes/IAcmeRenewalService.cs:7](Certes/IAcmeRenewalService.cs#L7)) — the
  background loop that renews each route before expiry and exposes the current
  default-route leaf.
- **`AcmeChallengeApprovalMiddleware`** ([Certes/AcmeChallengeApprovalMiddleware.cs:9](Certes/AcmeChallengeApprovalMiddleware.cs#L9))
  serves `http-01` tokens from `/.well-known/acme-challenge/{token}`.
- **`IDnsChallengeProvider` / `NullDnsChallengeProvider`**
  ([Certes/IDnsChallengeProvider.cs:26](Certes/IDnsChallengeProvider.cs#L26),
  [Certes/NullDnsChallengeProvider.cs:12](Certes/NullDnsChallengeProvider.cs#L12)) —
  a pluggable `dns-01` TXT-record provider; the null provider is the safe default.
- **`KestrelOptionsSetup`** ([KestrelOptionsSetup.cs:11](KestrelOptionsSetup.cs#L11))
  selects the server certificate by SNI (per-route, with a `__default__` fallback).
- **`CertificateProvider` / `IProvideCertificates`**
  ([Certificates/CertificateProvider.cs:12](Certificates/CertificateProvider.cs#L12),
  [Certificates/IProvideCertificates.cs:7](Certificates/IProvideCertificates.cs#L7))
  and `CertificateValidator` perform the actual renewal via
  `RenewCertificateIfNeeded`.

## Usage

Register the client, a persistence strategy for certificates and challenges, and
the challenge middleware:

```csharp
using OpenCertServer.Acme.AspNetClient;
using OpenCertServer.Acme.AspNetClient.Certes;
using CertesSlim.Extensions;

var options = new LetsEncryptOptions
{
    Email = "you@example.com",
    AccountPassword = "change-me",
    Domains = ["example.com"],
    CertificateSigningRequest = new CsrInfo
    {
        CountryName = "US",
        Organization = "Example Corp",
        State = "CA",
        Locality = "San Francisco",
    },
};

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();                       // the client factory needs one
builder.Services
    .AddAcmeClient(options)
    .AddAcmeFileCertificatePersistence("change-me", "acme-certificates")
    .AddAcmeFileChallengePersistence("acme-challenges");

var app = builder.Build();
app.UseAcmeClient();                                    // answers http-01 challenges
app.Run();
```

For `dns-01`, register a real `IDnsChallengeProvider` with
`AddAcmeClient(options, sp => MyDnsProvider.Instance)`; the null provider leaves
`http-01` untouched. The per-route YARP variant (one certificate per
`RouteConfig`, SNI-selected) is documented in
[`opencertserver.acme.yarp`](../opencertserver.acme.yarp/README.md).

## Dependencies

- `Microsoft.AspNetCore.App` — framework reference
  ([opencertserver.acme.aspnetclient.csproj:9](opencertserver.acme.aspnetclient.csproj#L9)).
- Project references: [`CertesSlim`](../CertesSlim/README.md),
  [`opencertserver.acme.abstractions`](../opencertserver.acme.abstractions/README.md),
  and `opencertserver.ca.utils`
  ([opencertserver.acme.aspnetclient.csproj:12-14](opencertserver.acme.aspnetclient.csproj#L12)).

This is a library. It is consumed by any ASP.NET Core host that wants ACME
auto-renewal, and is the foundation the per-route
[`opencertserver.acme.yarp`](../opencertserver.acme.yarp/README.md) integration
builds on.
