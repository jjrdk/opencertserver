# opencertserver.ra.server

A standalone **registration authority** that runs as its own process and delegates
every enrollment to a central certificate authority over a trusted HTTPS connection.
The RA never loads a CA key: it forwards a proof-of-possession CSR to the backing CA,
which enforces scope and identity and signs. The RA also serves the RFC 7030 EST
endpoints, so an EST client can enroll through the RA instead of the CA.

This is the "RA ↔ backing CA" and "RA serving EST ↔ backing CA" topologies from
[`docs/architecture-separation.md`](../../docs/architecture-separation.md).

## What runs here

- **Backed by the CA client.** `AddCaClient` registers the backing-CA
  [`CaClient`](../opencertserver.ca.client/README.md) and exposes it as this host's
  `ICertificateAuthority` (a `RemoteCertificateAuthority`), so the EST
  `/cacerts`, `/csrattrs` and `/simpleenroll` handlers resolve through the CA.
- **Outbound RA delegator.** `AddRaPeerClient` registers the
  [`RaPeerClient`](../opencertserver.ra/README.md) that forwards scoped enrollment to
  the CA.
- **EST surface.** `AddEstServer` plus `MapEstServer` serves `/.well-known/est/*`;
  `/cacerts` and `/csrattrs` are anonymous (RFC 7030 §3.1 bootstrap) and enrollment,
  re-enrollment and server keygen require a bearer token.
- **RA front endpoints.** `POST /ra/enroll?profile=<name>` reads a proof-of-possession
  CSR, forwards it to the backing CA (profile falls back to `Ca:Profile`), and returns
  the signed chain as a PEM; `GET /ra/profiles` returns the profiles the backing CA
  currently supports.
- **Fail-closed authentication.** `ConfigureRaJwt` guards the EST enrollment endpoints
  with a **signature-verified** JWT: the RA refuses to start unless a signing key
  (`Jwt:SymmetricKey` for HS256/384/512, or `Jwt:Authority` / `Jwt:MetadataAddress`
  for an asymmetric issuer) is configured. A token whose signature cannot be verified
  is rejected, so the RA can never accept a well-formed but unverified token.

## Configuration

| Key | Required | Meaning |
|---|---|---|
| `Ca:RemoteUrl` | yes | Absolute HTTPS URL of the backing CA. |
| `Ca:Profile` | no | Default issuance profile forwarded to the CA when a request names none. |
| `Ca:DelegatedScope` | no | Delegated scope the CA enforces on the RA's requests. |
| `Ca:BearerToken` / `Ca:ClientCert` | no | Trusted-connection secret / mTLS identity. |
| `Jwt:SymmetricKey` | one of | Symmetric key for HS256/384/512 EST enrollment tokens. |
| `Jwt:Authority` / `Jwt:MetadataAddress` | one of | Asymmetric issuer; signing keys are fetched from discovery metadata. `Jwt:ValidIssuers` narrows valid issuers. |

The RA refuses to start when **neither** a symmetric key nor an issuer is configured.
As environment variables these read as `Ca__RemoteUrl`, `Jwt__SymmetricKey`, and so on.

## Run

```sh
dotnet run --project src/opencertserver.ra.server -- --urls https://0.0.0.0:7200
```

Set the backing-CA and JWT configuration through the `Ca` and `Jwt` sections (or the
equivalent `Ca__*` / `Jwt__*` environment variables). The RA hosts no CA key and serves
`/ra/enroll`, `/ra/profiles` and the EST endpoints; see
[`docs/architecture-separation.md`](../../docs/architecture-separation.md)
§"Setting up an RA that serves EST against a backing CA" for the full setup, and
[`opencertserver.ra`](../opencertserver.ra/README.md) for the outbound peer client.

## Dependencies

- `opencertserver.ca.client` — the backing-CA HTTP client.
- `opencertserver.est.server` — the EST endpoints the RA serves.
- `opencertserver.ra` — the outbound RA peer client.
- `Microsoft.AspNetCore.Authentication.JwtBearer` (framework reference
  `Microsoft.AspNetCore.App`).

This is an application host, not a library.
