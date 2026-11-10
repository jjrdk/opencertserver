# opencertserver.acme.server

The **ACME (RFC 8555) server** for OpenCertServer. It is a library that exposes
the RFC 8555 endpoints (directory, account, order, challenge, revocation) and
**delegates issuance to whatever the host registers** — so the exact same code
runs as an in-process monolith next to a CA core
([`opencertserver.certserver`](../opencertserver.certserver/README.md)) or as a
standalone remote-CA host ([`opencertserver.acme`](../opencertserver.acme/README.md)).
Its root namespace is `OpenCertServer.Acme.Server`
([opencertserver.acme.server.csproj:4](opencertserver.acme.server.csproj#L4)).

## What runs here

### Registration and middleware

- **`ServiceCollectionExtensions.AddAcmeServer`**
  ([Extensions/ServiceCollectionExtensions.cs:27](Extensions/ServiceCollectionExtensions.cs#L27))
  reads the `AcmeServer` configuration section (optionally `PublicRa`) and registers
  the account / order / nonce / revocation services, the challenge validators, the
  CAA validator and DNS resolver, and an empty
  [`IAttestationTrustProvider`](../opencertserver.acme.abstractions/README.md)
  ([Extensions/ServiceCollectionExtensions.cs:132](Extensions/ServiceCollectionExtensions.cs#L132)).
  It deliberately does **not** register `ICsrValidator` or `IIssueCertificates` —
  those are the host's responsibility.
- **`AddAcmeInMemoryStore`** ([Extensions/ServiceCollectionExtensions.cs:178](Extensions/ServiceCollectionExtensions.cs#L178))
  and **`AddAcmeFileStore`**
  ([Extensions/ServiceCollectionExtensions.cs:163](Extensions/ServiceCollectionExtensions.cs#L163))
  register the store implementations (in-memory singletons, or file-backed
  `NonceStore` / `AccountStore` / `OrderStore` / `ExternalAccountKeyStore`).
- **`AcmeRegistration.UseAcmeServer`**
  ([AcmeRegistration.cs:12](AcmeRegistration.cs#L12)) maps the endpoints under an
  optional path base, with the ACME response / index / validation endpoint filters.

### Endpoints (`Endpoints/`)

The RFC 8555 paths, all `AllowAnonymous` (ACME authenticates via JWS, not ASP.NET
authentication):

| Endpoint | Path | File |
|---|---|---|
| Directory | `GET /directory` | [DirectoryEndpoints.cs:16](Endpoints/DirectoryEndpoints.cs#L16) |
| New nonce | `GET /new-nonce` | [NonceEndpoints.cs:41](Endpoints/NonceEndpoints.cs#L41) |
| New account | `POST /new-account` | [AccountEndpoints.cs:28](Endpoints/AccountEndpoints.cs#L28) |
| Key change | `POST /key-change` | [AccountEndpoints.cs:30](Endpoints/AccountEndpoints.cs#L30) |
| Account orders | `POST /account/{accountId}/orders` | [AccountEndpoints.cs:38](Endpoints/AccountEndpoints.cs#L38) |
| New order | `POST /new-order` | [OrderEndpoints.cs:25](Endpoints/OrderEndpoints.cs#L25) |
| Order / auth / challenge | `POST /order/{orderId}`, `/auth/{authId}`, `/auth/{authId}/chall/{challengeId}` | [OrderEndpoints.cs:90](Endpoints/OrderEndpoints.cs#L90) |
| Finalize / certificate | `POST /order/{orderId}/finalize`, `/certificate` | [OrderEndpoints.cs:214](Endpoints/OrderEndpoints.cs#L214) |
| Revoke | `POST /revoke-cert` | [RevocationEndpoints.cs:17](Endpoints/RevocationEndpoints.cs#L17) |

### Challenge validators (`Services/`)

Token-based challenges share an abstract
[`TokenChallengeValidator`](Services/TokenChallengeValidator.cs#L13)
(account-must-be-valid, expiry, key-authorization comparison):

- **`ValidateHttp01Challenges`** ([Services/Http01ChallengeValidator.cs:15](Services/Http01ChallengeValidator.cs#L15)) —
  fetches the key authorization over an SSRF-blocking HTTP client; expected content
  is `{token}.{jwkThumbprint}`.
- **`ValidateDns01Challenges`** ([Services/Dns01ChallengeValidator.cs:17](Services/Dns01ChallengeValidator.cs#L17)) —
  expected content is `base64url(SHA256(keyAuthorization))`, looked up via the
  multi-perspective `IDnsResolver` (DnsClientX).
- **`DeviceAttestChallengeValidator`** ([Services/DeviceAttestChallengeValidator.cs:21](Services/DeviceAttestChallengeValidator.cs#L21)) —
  verifies `device-attest-01` evidence (nonce → TPM quote → AIK signature → AIK
  chain) against the registered `IAttestationTrustProvider`, with replay protection.
- **`CaaValidator`** ([Services/CaaValidator.cs:45](Services/CaaValidator.cs#L45)) —
  RFC 8659 / RFC 8657 CAA processing (Relevant RRset, `issue` / `issuewild`,
  `accounturi`, `validationmethods` with BR `ca-tbr-*` aliases).

### Issuance delegation

[`DefaultOrderService`](Services/DefaultOrderService.cs#L17) is where the
topology lives. On finalize it validates the CSR through the injected
`ICsrValidator` ([Services/DefaultOrderService.cs:165](Services/DefaultOrderService.cs#L165))
and then signs through the injected `IIssueCertificates`
([Services/DefaultOrderService.cs:172](Services/DefaultOrderService.cs#L172)).
Neither `ICsrValidator` nor `IIssueCertificates` has a concrete implementation in
this project — the in-process `DefaultCsrValidator` / `DefaultIssuer` live in
`opencertserver.certserver` and the remote `RemoteIssuer` lives in
[`opencertserver.acme.remote`](../opencertserver.acme.remote/README.md), which is
exactly what lets one server serve both topologies.

The remaining pieces are the store implementations (`Stores/`), the background
validation loop (`BackgroundServices/HostedValidationService`,
`Workers/ValidationWorker`), and the SSRF / multi-perspective DNS plumbing
(`Services/SsrfBlockingSocketsHandler`, `Services/MultiPerspectiveDnsResolver`).

## Usage

The in-process variant (the monolith) registers the server, an in-memory store,
and the CA-backed issuance seam, then maps the endpoints:

```csharp
using OpenCertServer.Acme.Server;
using OpenCertServer.Acme.Server.Extensions;
using OpenCertServer.Acme.Abstractions.IssuanceServices;

var builder = WebApplication.CreateBuilder(args);

// The in-process issuer/CSR validator come from opencertserver.ca / certserver.
builder.Services
    .AddAcmeServer(builder.Configuration)   // reads the "AcmeServer" section
    .AddAcmeInMemoryStore()                 // or .AddAcmeFileStore(builder.Configuration)
    .AddSingleton<ICsrValidator, DefaultCsrValidator>()
    .AddSingleton<IIssueCertificates, DefaultIssuer>();

var app = builder.Build();
app.UseAcmeServer();                        // maps the RFC 8555 endpoints
app.Run();
```

The remote-CA variant — `AddAcmeServer` + `AddAcmeInMemoryStore` +
`AddAcmeRemoteCa` (which registers `RemoteIssuer` as `IIssueCertificates`) +
`UseAcmeServer` — is documented in
[`opencertserver.acme`](../opencertserver.acme/README.md). The per-route YARP
topology is in [`opencertserver.acme.yarp`](../opencertserver.acme.yarp/README.md).

## Dependencies

- `DnsClientX` — package reference for `dns-01` / CAA DNS resolution
  ([opencertserver.acme.server.csproj:11](opencertserver.acme.server.csproj#L11)).
- `Microsoft.AspNetCore.App` — framework reference
  ([opencertserver.acme.server.csproj:15](opencertserver.acme.server.csproj#L15)).
- Project references: [`CertesSlim`](../CertesSlim/README.md),
  [`opencertserver.acme.abstractions`](../opencertserver.acme.abstractions/README.md),
  `opencertserver.ca.utils`, and `opencertserver.tss.net` (TPM/attestation)
  ([opencertserver.acme.server.csproj:19-22](opencertserver.acme.server.csproj#L19)).

This is a library, not an application. The hosts that run it are
[`opencertserver.acme`](../opencertserver.acme/README.md) (remote-CA host) and
[`opencertserver.certserver`](../opencertserver.certserver/README.md)
(in-process monolith).
