# opencertserver.scep

A standalone SCEP server (RFC 8894) that holds **no CA key**. It forwards
enrollment and renewal to a **backing CA** over a trusted HTTPS connection, exactly
like the `opencertserver.acme` and `opencertserver.ra.server` hosts. The CA stays
authoritative for scope, identity, and the published chain; the SCEP host is only a
transport.

## What runs here, and what stays local

The SCEP host serves `/scep` (and the Windows `/scep/pkiclient.exe` form), GET and
POST, plus `/scep/{profile}` for a named profile.

Stays **local** to this host (not CA authority):

- **The SCEP RA certificate (RSA).** Clients encrypt their request to it and the
  host signs responses with it. Load it from `--scep-ra` / `--scep-ra-key`; when no
  key is supplied a transient one is made (matching the ACME RA cert).
- **The challenge validator** — a shared secret (`Scep:Challenge`) or Intune
  (`Scep:Intune`). `PKIOperation` issues nothing until a challenge is configured.
- **The replay store.** A window of accepted transaction IDs + sender nonces so a
  captured `PKCSReq`/`RenewalReq` cannot be replayed (`ScepServerOptions`).

Delegated to the **backing CA**:

- Issuance and renewal. A `RenewalReq` supersedes the previous certificate **at the
  CA**; the previous cert is forwarded via the `X-Reenrolling-From` header so the CA
  supersedes-revokes it.
- The published chain. `GetCACert` returns `GET /ca/published` from the CA, so the CA
  stays authoritative for what is published.
- Revocation. The optional Intune sync (`POST /scep/intune/sync`) revokes through the
  backing CA's `ICertificateAuthority`.

## Configuration

| Key | Meaning |
|---|---|
| `Ca:RemoteUrl` | Absolute HTTPS URL of the backing CA (required). |
| `Ca:Profile` | Default profile forwarded when the request names none. |
| `Ca:DelegatedScope` | Scope the CA enforces on this host's requests. |
| `Ca:BearerToken` / `Ca:ClientCert` | Trusted-connection secret / mTLS identity. |
| `Scep:Challenge` | Shared-secret challenge. When set, it replaces the "not configured" validator. |
| `Scep:DefaultProfile` | SCEP profile used when the path names none (default `rsa`). |
| `Scep:Intune:*` | When `TenantId` is configured, Intune replaces the challenge and the host also maps the revocation sync. |

The SCEP RA cert is a command-line concern: `--scep-ra <cert.pem> --scep-ra-key
<key.pem>`.

## Run

```sh
dotnet run --project src/opencertserver.scep -- --urls https://0.0.0.0:7100
```

A SCEP client enrolls through `/scep`; the host forwards the CSR to the CA, which
enforces scope/identity and signs. See
[`../docs/architecture-separation.md`](../docs/architecture-separation.md) §"Setting
up a SCEP host against a backing CA".

## The monolith keeps SCEP on by default

The `opencertserver.certserver` monolith enables SCEP unless `Scep:Enabled=false`
(CA-only host). The gate decision (`IsScepEnabled`) also drives
`MapScepServer`/`MapIntuneSync` in the monolith; this host maps SCEP unconditionally.
See `tests/opencertserver.certserver.tests/Features/ScepComposition.feature`.
