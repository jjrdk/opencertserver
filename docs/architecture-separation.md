# Separating RA / CA / ACME

This document describes the RA/CA/ACME separation: three trust roles that can be
deployed as one process (the default monolith) or split across hosts that talk to
each other over **trusted HTTPS connections**. The invariant from
[`separate-ra-ca-acme-plan.md`](../separate-ra-ca-acme-plan.md) holds throughout:
**the CA stays authoritative for scope and identity; RA/ACME checks are
conveniences, never the source of truth.** The CA's `CaClient` performs the
*second, authoritative* check for every request a peer forwards.

## Topologies

| Topology | How to run it | Process(es) |
|---|---|---|
| **Monolith** (default) | `opencertserver.certserver` with no `AcmeServer:Issuer` set | one: CA core + EST + ACME (in-process issuer) + RA + PublicRa |
| **ACME ↔ backing CA** | `opencertserver.acme` host, or `certserver` with `AcmeServer:Issuer=remote` | ACME server + a separate CA |
| **RA ↔ backing CA** | `opencertserver.ra.server` host | RA + a separate CA |
| **RA serving EST ↔ backing CA** | `opencertserver.ra.server` host (serves `/.well-known/est/*`) | RA + a separate CA |
| **SCEP ↔ backing CA** | `opencertserver.scep` host (serves `/scep`), or `certserver` with a `Scep` config | SCEP server + a separate CA |

## Project map

| Project | Role | Depends on CA core? |
|---|---|---|
| `opencertserver.ca.client` | `ICertificateAuthority`/`IRevocationService` over HTTP(S) + a `CaClient` HttpClient with revocation PoP signing | no (ca.utils only) |
| `opencertserver.ra` | RA peer client + policy; RA host wiring | no |
| `opencertserver.acme.remote` | `RemoteIssuer` (`IIssueCertificates`) that delegates to a `CaClient`; `AddAcmeRemoteCa` | no (via ca.client) |
| `opencertserver.acme` | Standalone ACME server host (no ca core); issues via a remote CA | no |
| `opencertserver.ra.server` | Standalone RA host; forwards CSR to a backing CA + RA peers; **serves EST** (`/.well-known/est/*`) over the backing CA | no |
| `opencertserver.scep` | Standalone SCEP host (RFC 8894); forwards enrollment/renewal to a backing CA, holds only the SCEP RA cert + challenge + replay store; **no CA core** | no (via ca.client) |
| `opencertserver.certserver` | In-process monolith; `AcmeServer:Issuer=remote` opts the ACME surface onto a backing CA | yes |

The new remote projects depend on `opencertserver.ca.client` and **not** on
`opencertserver.ca`; the AOT-published `certserver`/`est.server` are unaffected.

## The trusted connection (plan §7)

Every RA↔CA / ACME↔CA / RA↔RA call rides a trusted connection:

- **HTTPS** — the `CaClient`/`RaPeerClient`/`RemoteIssuer` base URLs must be
  absolute `https://` (`CaClientOptions`/`RaPeerOptions` enforce this in
  `FromConfiguration` and `Validate`).
- **Auth** — a shared **bearer** token (`Ca:BearerToken` / `Ra:BearerToken`) and/or
  **mTLS** client certificate (`Ca:ClientCert`). The server side requires
  `JwtBearer` + certificate authentication (see `ConfigureJwtBearerOptions`,
  `ConfigureCertificateAuthenticationOptions` in `certserver`).
- **Revocation PoP** — revocation is signed by the `CaClient`'s revoke identity
  (a certificate with a private key, `Ca:ClientCert`); the CA verifies the
  signature (see `RemoteRevocationService.VerifyRevocationSignature`).

## Configuration keys

### `opencertserver.ca.client` (used by the ACME host, the RA host, and the monolith's remote issuer)

| Key | Required | Meaning |
|---|---|---|
| `Ca:RemoteUrl` (or `Ca:BaseUrl`) | yes | Absolute HTTPS URL of the backing CA (`/ca/csr`, `/ca/revoke`, `/ca/crl`, `/ca/ocsp`). |
| `Ca:Profile` | no | Issuance profile name. |
| `Ca:Profiles` | no | Comma-separated delegated profile set this client may use; empty means **all** profiles the CA supports. Refreshable on demand via `CaClient.GetProfiles` (see "Profile discovery"). |
| `Ca:DelegatedScope` | no | Delegated scope (host / `*.wildcard.example.com` / `*`); enforced by the CA's RA-scope validator. |
| `Ca:BearerToken` | no | Shared secret / JWT bearer for the trusted connection. |
| `Ca:Trust` | no | Path to a PEM bundle of CA trust anchors (PEM → `TrustCertPath`). |
| `Ca:ClientCert` | no | PFX path for the client cert (revocation PoP + mTLS). |
| `Ca:ClientCertPassword` | no | PFX password. |
| `Ca:RootsPath` | no | Local CA certificate directory (default `cacerts`). |
| `Ca:RevocationListPath` | no | Local revocation-list directory (default `ca/crl`). |

### `opencertserver.ra` peer client

| Key | Required | Meaning |
|---|---|---|
| `Ra:PeerUrl` | yes | Absolute HTTPS URL of a peer RA. |
| `Ra:Scope` | yes | The scope this peer RA is delegated. |
| `Ra:Profile` | no | Issuance profile (default when a request names none). |
| `Ra:Profiles` | no | Comma-separated delegated profile set this RA may use; empty means **all** profiles the CA supports. Refreshable on demand via `RaPeerClient.GetSupportedProfiles`. |
| `Ra:BearerToken` | no | Shared secret / JWT bearer. |

### `opencertserver.certserver` (monolith)

| Key | Default | Meaning |
|---|---|---|
| `AcmeServer:Issuer` | (empty / `inproc`) | `remote` selects `RemoteIssuer` (issues through `Ca:RemoteUrl`); empty/`inproc` keeps the in-process `DefaultIssuer`. |
| `Scep:Enabled` | on | Opt the SCEP surface (`/scep`) and the optional Intune sync on/off in the monolith. Absent = on (preserves T1); `false` runs a CA-only host with `/ca/*` and no `/scep`. `true` forces it on regardless of any `Scep:Challenge`/`Scep:Intune`/`--scep-ra` presence. The same decision gates `AddScep` registration and `MapScepServer`/`MapIntuneSync` mapping. |

The `opencertserver.acme` host always uses the remote issuer (no in-process CA).
The `opencertserver.scep` host always maps SCEP unconditionally (it is the SCEP host); a
CA-only `certserver`/`ca.server` deployment instead sets `Scep:Enabled=false` so it serves
`/ca/*` with no `/scep`.

### `opencertserver.ra.server` (RA host, EST + backing CA)

The RA host serves the RFC 7030 EST endpoints (`/.well-known/est/cacerts`,
`/csrattrs`, `/simpleenroll`, `/simplereenroll`, `/serverkeygen`) and delegates
**all** issuance to the backing CA. EST handlers take the issuing authority from
`ICertificateAuthority`, which `AddCaClient` provides as a
`RemoteCertificateAuthority` — so `/cacerts` returns the CA's chain and
`/simpleenroll` is signed by the CA over the trusted connection. The RA never loads
a CA key.

| Key | Default | Meaning |
|---|---|---|
| `Ca:RemoteUrl` | — | Absolute HTTPS URL of the backing CA (required). |
| `Ca:Profile` | `rsa` | Default issuance profile forwarded to the CA when a request names none. |
| `Ca:DelegatedScope` | — | Delegated scope the CA enforces on the RA's requests. |
| `Ca:BearerToken` / `Ca:ClientCert` | — | Trusted-connection secret / mTLS identity. |
| `Jwt:SymmetricKey` | (empty) | When set, EST enrollment tokens are signature-validated. When empty the RA requires a well-formed JWT but does not verify its signature, leaving identity authority with the backing CA. |

`/cacerts` and `/csrattrs` are anonymous (RFC 7030 §3.1 bootstrap);
`/simpleenroll`, `/simplereenroll`, and `/serverkeygen` require a bearer
(`JwtBearer`) token.

### Profile discovery and multi-profile RAs

An RA need not be pinned to a single profile. The RA host offers the **full** set
of profiles the backing CA supports:

- **Per-request profile** — `POST /ra/enroll?profile=<name>` (and the underlying
  `RaPeerClient.EnrollAsync(csr, profile)`) routes a single request to
  `/{profile}/csr` on the CA. With no `profile` it falls back to `Ca:Profile`
  (then the CA's default). One RA therefore serves several profiles.
- **Discovery** — `GET /ra/profiles` asks the backing CA for its current profile
  set (`GET /ca/profiles`, returned as newline-delimited names) and returns it, so
  an RA can learn the profiles it may offer and **refresh** that set on demand
  (the CA may add or remove profiles between calls). The RA's `Ca:Profiles` /
  `Ra:Profiles` delegated set is empty by default, which means *all* profiles the
  CA supports; a non-empty set restricts the RA to a subset.
- **Wire contract** — `GET /ca/profiles` is authenticated like `/ca/csr`
  (`RequireAuthenticatedUser`) and returns only profile **names**; the profile
  material (keys, chains, validity) never crosses the wire.

### Setting up an RA that serves EST against a backing CA

1. Run a backing CA that exposes `/ca/csr`, `/ca/revoke`, `/ca/crl`, `/ca/ocsp`
   (any `certserver`/`ca.server` deployment with JWT + certificate auth on those
   routes).
2. Run the RA host pointing at it:
   ```sh
   dotnet run --project src/opencertserver.ra.server \
       -- --urls https://0.0.0.0:7000
   ```
   with `appsettings.json`:
   ```json
   {
     "Ca": {
       "RemoteUrl": "https://ca.example.com/",
       "Profile": "rsa",
       "DelegatedScope": "tenant-a.example.com",
       "BearerToken": "<shared secret with the CA>",
       "ClientCert": "/etc/ra/ra.pfx"
     },
     "Jwt": { "SymmetricKey": "…base64 32-byte key…" }
   }
   ```
3. Clients enroll through the RA's EST surface:
   ```sh
   est-enroll --url https://ra.example.com:7000 --auth "$TOKEN"
   ```
   The RA forwards the CSR to the CA; the CA enforces scope/identity and signs.
   The RA serves every profile the CA supports: a request may name one via
   `?profile=<name>` (otherwise `Ca:Profile` / the CA default is used), and the
   RA's current profile set can be read or refreshed at any time with
   `GET /ra/profiles` (which the RA fetches from `GET /ca/profiles` on the CA).

### What stays local to a remote SCEP / ACME host (WP7)

A host that talks to a backing CA holds **no CA key**. The things that are *not*
CA authority stay local, exactly like the ACME and RA hosts:

- **SCEP RA certificate (RSA).** The SCEP client encrypts its request to this cert
  and the server signs its responses with it. It is an identity of the SCEP host,
  loaded from `--scep-ra` / `--scep-ra-key` (a transient one is made when no key is
  supplied, matching the ACME RA cert).
- **The challenge validator** — a shared secret (`Scep:Challenge`) or Intune
  (`Scep:Intune`). PKIOperation issues nothing until a challenge is configured.
- **The replay store.** A window of accepted transaction IDs + sender nonces so a
  captured PKCSReq/RenewalReq cannot be replayed (see `ScepServerOptions`).

The published chain a remote SCEP/EST peer needs to reach the root is **not**
rebuilt locally — the CA publishes it:

- **`GET /ca/published`** (and `GET /ca/{profile}/published`) returns the full
  published chain for a profile (issuing CA + root, and any published
  intermediates) as a PEM bundle. It is authenticated exactly like `POST /ca/csr`
  (`RequireAuthenticatedUser`), so a remote peer cannot enumerate the published
  chain without the CA trusting its identity. `RemoteCertificateAuthority` calls
  `GET /ca/published` (via `ICertificateAuthority.GetPublishedCertificates`) for its
  GetCACert chain and renewal anchors, so the CA stays authoritative for what is
  published.
- **`X-Reenrolling-From` header.** Re-enrollment carries the *previous* certificate
  to the CA so a `RenewalReq` supersedes it (superseding-revokes) at the CA. The
  remote authority forwards it as the `X-Reenrolling-From` request header
  (`RaProtocol.ReenrollingFromHeader`, a PEM-encoded previous cert); `CsrHandler`
  reads it and passes it to `ca.SignCertificateRequest(..., reenrollingFrom:
  previous)`. This is a **documented deviation from the plan's §10 Q6 JSON envelope**
  — a header is the transport actually used, and it is the only thing that crosses
  the wire for re-enrollment.

### Setting up a SCEP host against a backing CA

1. Run a backing CA that exposes `/ca/csr`, `/ca/revoke`, `/ca/crl`, `/ca/ocsp`,
   and **`/ca/published`** (any `certserver`/`ca.server` deployment with JWT +
   certificate auth on those routes).
2. Run the SCEP host pointing at it:
   ```sh
   dotnet run --project src/opencertserver.scep \
       -- --urls https://0.0.0.0:7100
   ```
   with `appsettings.json`:
   ```json
   {
     "Ca": {
       "RemoteUrl": "https://ca.example.com/",
       "Profile": "rsa",
       "DelegatedScope": "tenant-a.example.com",
       "BearerToken": "<shared secret with the CA>",
       "ClientCert": "/etc/scep/ra.pfx"
     },
     "Scep": {
       "Challenge": "<shared secret, or set the Intune section>"
     }
   }
   ```
   The SCEP RA cert is loaded from `--scep-ra` / `--scep-ra-key` on the command
   line (a transient one is made when no key is supplied). With `Scep:Intune`
   configured instead of `Scep:Challenge`, the host also maps
   `POST /scep/intune/sync` (the Intune revocation sync).
3. SCEP clients enroll through `/scep` (and the Windows `/scep/pkiclient.exe`
   form). The host forwards the CSR to the CA over the trusted connection; the CA
   enforces scope/identity and signs, and a `RenewalReq` supersedes the previous
   certificate at the CA via `X-Reenrolling-From`.

## BDD proofs

| Feature | Proves |
|---|---|
| `tests/…/Features/CaClient.feature` | HTTP `CaClient` issues/renews; **remote ACME issuer delegates to the backing CA**; revocation over HTTP needs a PoP identity and a trusted-connection secret; revocation without a PoP identity is refused. |
| `tests/…/Features/AcmeRemoteCa.feature` | The ACME-side `RemoteIssuer` finalizes an order through a backing CA; an **out-of-scope identifier fails the order** with an ACME error; a certificate is **revoked over the wire**; a **non-HTTPS backing CA is rejected at startup**. |
| `tests/…/Features/RaServer.feature` | The RA host forwards an in-scope enrollment to the backing CA; an **out-of-scope subject is rejected (400)**; a renewal re-applies CA policy; the RA host enforces **HTTPS-only** transport to the CA. |
| `tests/…/Features/RaMultiProfile.feature` | An RA **requests the CA's supported profile set** (discovery/refresh) and **enrolls against a non-default profile** by name, proving one RA serves several profiles. |
| `tests/…/Features/Monolith.feature` | The default in-process monolith still issues an in-scope certificate and **rejects an anonymous `/ca/csr`** (T1 regression guard). |
| `tests/…/Features/ScepRemoteCa.feature` | A SCEP host pointed at a backing CA **enrolls in scope** (the backing CA issues the chain); a `RenewalReq` **supersedes the previous certificate at the CA**; an **out-of-scope subject is refused**; `GetCACert` returns the **full published chain**; a **non-HTTPS backing CA is rejected at startup**; and a **replay is refused by the local replay store**. |
| `tests/…/Features/ScepComposition.feature` | The monolith **enables SCEP by default** (T1) and on any `Scep` config; a **CA-only host** (`Scep:Enabled=false`) **disables SCEP** even when a challenge is present — the same `IsScepEnabled` decision gates both `AddScep` registration and `MapScepServer`/`MapIntuneSync` mapping. |
| `tests/…/Features/IntuneRevocationSync.feature` | The Intune revocation sync **revokes through the `ICertificateAuthority`** the host is wired with (a `RemoteCertificateAuthority` over a backing CA for a separated deployment, the in-proc CA otherwise), so a disabled/deleted user or retired/disabled device loses its certificate **at the backing CA**; unknown is never revoked. |
| `opencertserver.acme` / `opencertserver.ra.server` / `opencertserver.scep` hosts | Build clean. `opencertserver.ra.server` (now **including its EST surface**) AOT-publishes to a native binary; its EST handlers delegate to the backing CA through the same `ICertificateAuthority` that the remote-issuer and CA-client features prove. `opencertserver.acme` is framework-dependent only: it transitively pulls `DnsClientX` (dns-01 in `acme.server`), which is not AOT-compatible — a pre-existing property of `acme.server`, not of the separation. |

## Telemetry

The trusted remote link is metered by `opencertserver.ca.client` (meter
`opencertserver.ca.client`, counters `opencertserver.ca.client.sign` and
`opencertserver.ca.client.revoke`, tagged `result=success|rejected|revoked|not_found|error`).
The monolith registers the meter in `RegisterTelemetry` when `Telemetry:Enabled=true`; a
standalone host exports it with
`builder.Services.AddOpenTelemetry().WithMetrics(m => m.AddMeter("opencertserver.ca.client"))`.


## Extending a peer to a full RA

`opencertserver.ra.server` is a *forwarding* RA (delegates issuance to a backing
CA and RA peers). To make it a *full* RA that issues its own certificates, add
the CA core and an in-process issuer:

```csharp
builder.Services
    .AddCertificateAuthority()
    .AddRa(options => { /* trust anchors, scope policy */ })
    .AddSingleton<IIssueCertificates, DefaultIssuer>();
```

The RA-scope validator (`RaScopeValidator`) keeps the CA authoritative: the RA
never grants scope the CA hasn't delegated.
