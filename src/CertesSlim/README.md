# CertesSlim

A lightweight .NET client library for the **ACME (RFC 8555)** protocol: JWS
signing, the account / order / challenge flow, and the key + CSR helpers OpenCertServer
needs on the client side. OpenCertServer maintains it **in-repo as a fork of the
upstream [`fszlin/certes`](https://github.com/fszlin/certes) project** — the
csproj keeps the upstream metadata (`Authors`, `Product`, `RepositoryUrl`,
MIT license) — and has adapted it for this repository: profile-specific
requests, the DNS-01 client path, source-generated (AOT/trim-safe) JSON, and
hardware-attestation support. It is **not** a pristine vendored snapshot and is
**not** presented as OpenCertServer-authored; the canonical upstream is
[`fszlin/certes`](https://github.com/fszlin/certes). Its root namespace is
`CertesSlim` ([CertesSlim.csproj](CertesSlim.csproj)).

## What runs here

### Context and flow

- **`AcmeContext` / `IAcmeContext`** ([AcmeContext.cs:15](AcmeContext.cs#L15),
  [IAcmeContext.cs:11](IAcmeContext.cs#L11)) — the entry point. Constructed with
  `(directoryUri, accountKey?, http?, badNonceRetryCount)`; exposes
  `Account()`, `GetDirectory()`, `NewAccount(…)` and `NewOrder(profile, identifiers)`
  ([AcmeContext.cs:202](AcmeContext.cs#L202)).
- **Context types** (`Acme/`) — `IAccountContext`
  ([Acme/IAccountContext.cs:8](Acme/IAccountContext.cs#L8)), `IOrderContext`
  ([Acme/IOrderContext.cs:8](Acme/IOrderContext.cs#L8)), `IAuthorizationContext`,
  `IChallengeContext` ([Acme/IChallengeContext.cs:6](Acme/IChallengeContext.cs#L6))
  and `IOrderListContext`, each with a concrete `*Context` and the RFC 8555
  resource DTOs under `Acme/Resource/` (`Account`, `Order`, `Authorization`,
  `Challenge`, `Directory`, `Identifier`, …).
- **HTTP / JWS** ([Acme/AcmeHttpClient.cs](Acme/AcmeHttpClient.cs),
  [Acme/IAcmeHttpClient.cs:6](Acme/IAcmeHttpClient.cs#L6)) — nonce handling,
  JWS-signed `POST` / `GET`, and `badNonce` retry.

### Keys and CSR

- **`IKey` / `KeyFactory`** ([IKey.cs:9](IKey.cs#L9), [KeyFactory.cs:9](KeyFactory.cs#L9)) —
  `NewKey(algorithm, keySize?)` (ECDSA P-256/384/521, RSA 2048/3072/…) and
  `FromPem`; `Key.ToPem()` exports the key.
- **`ISignatureKeyExtensions`** ([ISignatureKeyExtensions.cs:10](ISignatureKeyExtensions.cs#L10)) —
  `Thumbprint()`, `KeyAuthorization(token)` and `DnsTxt(token)`.
- **`CertificationRequestBuilder`** ([Pkcs/CertificationRequestBuilder.cs:10](Pkcs/CertificationRequestBuilder.cs#L10)) —
  build a PKCS#10 request (names + SANs).
- **Extensions** (`Extensions/`) — the order-flow convenience methods:
  `NewAccount(email, …)` ([Extensions/IAcmeContextExtensions.cs:44](Extensions/IAcmeContextExtensions.cs#L44)),
  `Generate(csr, key, …)` ([Extensions/IOrderContextExtensions.cs:68](Extensions/IOrderContextExtensions.cs#L68)),
  and `Http()` / `Dns()` / `TlsAlpn()` / `Challenge(type)`
  ([Extensions/IAuthorizationContextExtensions.cs:18](Extensions/IAuthorizationContextExtensions.cs#L18)).

### Embedded roots

Three root CA certificates are embedded as resources for validation
([CertesSlim.csproj:18-26](CertesSlim.csproj#L18)): `dst-root-ca-x3`,
`fake-le-root-x1` and `isrg-root-x1`
([Resources/Certificates/](Resources/Certificates/)).

## Usage

Drive an ACME order through the library directly:

```csharp
using CertesSlim;
using CertesSlim.Acme;
using CertesSlim.Extensions;
using Microsoft.IdentityModel.Tokens;

// Point at a directory; a fresh ECDSA account key is generated when none is supplied.
var acme = new AcmeContext(
    new Uri("https://acme.example.com/directory"),
    KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256));

// 1. Register / reuse the account.
await acme.NewAccount("you@example.com", termsOfServiceAgreed: true);

// 2. Place an order and satisfy its challenges.
var order = await acme.NewOrder(profile: null, identifiers: ["example.com"]);
foreach (var authz in await order.Authorizations())
{
    var challenge = await authz.Http();            // or authz.Dns()
    // Serve challenge.KeyAuthz at / .well-known/acme-challenge/{challenge.Token}
    await challenge.Validate();
}

// 3. Finalize with a CSR and download the chain.
var certKey = KeyFactory.NewKey(SecurityAlgorithms.EcdsaSha256);
var chain = await order.Generate(new CsrInfo { CountryName = "US" }, certKey);
```

The higher-level, DI-driven flow (renewal, SNI, persistence) lives in
[`opencertserver.acme.aspnetclient`](../opencertserver.acme.aspnetclient/README.md).

## Dependencies

- `Microsoft.IdentityModel.Tokens` — package reference for `JsonWebKey` / JWS
  ([CertesSlim.csproj:34](CertesSlim.csproj#L34)).
- `Microsoft.SourceLink.GitHub` — private-asset build aid
  ([CertesSlim.csproj:30](CertesSlim.csproj#L30)).
- Embedded root CA certificates (above).

This is a foundational library. It is referenced directly by
[`opencertserver.acme.abstractions`](../opencertserver.acme.abstractions/README.md),
[`opencertserver.acme.server`](../opencertserver.acme.server/README.md) and
[`opencertserver.acme.aspnetclient`](../opencertserver.acme.aspnetclient/README.md).
Upstream: [`fszlin/certes`](https://github.com/fszlin/certes).
