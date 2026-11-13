# opencertserver.host.ca

A hardened **certificate-authority appliance**. It hosts the CA core and the CA-side RA
bindings, plus relational (PostgreSQL/MSSQL) or in-memory storage selected at runtime. It is
the **trust anchor only**: it serves the CA responder and never the EST enrollment, ACME, or
SCEP endpoints.

This host is one of the three per-role appliance hosts under `src/hosts/`. Splitting the
former `opencertserver.certserver` monolith into per-role hosts means the role that ships in an
image compiles only the middleware it serves, which shrinks the attack surface and the binary.
See [`docs/docker.md`](../../../docs/docker.md#host-projects-per-role) for the role→surface→
reference table.

## What runs here

- **The CA responder** — `UseCertificateAuthorityServer()` maps the `/ca` route group:
  `POST /ca/csr` (enrollment), `GET /ca/profiles`, `DELETE /ca/revoke`, `GET /ca/crl` and
  `GET /ca/{profile}/crl`, `GET /ca/published` and `GET /ca/{profile}/published`, and the OCSP
  responder `POST/GET /ca/ocsp`, plus `/health`.
- **The CA core** — `AddCaCore` builds the issuing CA. With a `dn` a self-signed CA is created at
  start-up; otherwise the configured RSA and ECDSA profiles and their trust anchors are loaded,
  exactly as the monolith did.
- **The CA-side RA bindings** — `AddRa` registers the RA role so a registration authority can
  delegate issuance and revocation to this CA over a trusted connection.
- **EST DI only, not the EST endpoints** — `AddEstServer<ConfiguredCsrTemplateLoader>()` is kept
  because it registers `ICsrTemplateLoader`, the root/published certificate factories, and
  `IEstTrustAnchorProvider`, all of which the CA responder needs. The EST *enrollment* surface
  (`/cacerts`, `/new-nonce`, `/simpleenroll`, `/serverkeygen`) comes from `UseEstServer`, which
  this host deliberately does **not** call — that surface belongs to the
  [`opencertserver.host.unified`](../opencertserver.host.unified/README.md) host.

## What it intentionally omits

- **EST enrollment** (`UseEstServer`) — a CA-only host is the trust anchor, not an enrollment
  front-end.
- **ACME** (`UseAcmeServer`) and **SCEP** (`MapScepServer`) — enrollment/revocation front-ends.
- The project references `opencertserver.ca.server`, `opencertserver.ca.utils`,
  `opencertserver.est.server`, and the data stores, but **never** `opencertserver.acme.server`
  or `opencertserver.scep.server`, so those surfaces cannot be added by mistake.

## Configuration

Configuration is read from the usual sources plus environment variables. The keys that matter for
this host:

| Key | Meaning |
|---|---|
| `Appliance:Hardened` | When true (the default) the host is TLS 1.3-only, omits the `Server` header, and audits every request. |
| `Appliance:Role` | Not read by this host; `Ca` is its role. The `Appliance:Role` gate lives in the Unified host. |
| `dn` | A distinguished name for a self-signed CA created at start-up. A hardened host forbids `dn` and requires persistent keys instead. |
| `rsa:…` / `ecdsa:…` | Per-profile PEM paths (`Pem`, `KeyPem`, `PublishedPem`) and the profile options (`KeyUsage`, `ExtendedKeyUsages`, `CertificatePolicies`, `TrustAnchors`, `AdditionalChainCertificates`, `AllowPublicEnrollment`). |
| `Ca:Persistence` | `memory` (default, in-memory store) or `relational`. |
| `Appliance:Engine` | Selects the relational engine when `Ca:Persistence=relational`: `postgres` (default) or `mssql`. |
| `ConnectionStrings:OpenCertServer` | The relational connection string, reached via the engine's `IStoreCertificates`. |
| `Jwt:Authority` / `Jwt:Audiences` | The operator identity provider. **Optional**: when unconfigured the host runs without operator JWT (EST / mTLS continue to work), mirroring the monolith's fallback. When configured, `Jwt:Authority` must be an HTTPS URL and at least one audience is required. |
| `CaServer:OCSP` / `CaServer:CrlDistributionPoints` / `CaServer:CaIssuers` | Seed the AIA/CDP defaults for issued certificates. |
| `Kestrel:Endpoints:*` / `port` | The HTTPS listener. A hardened host permits only HTTPS listeners. |

### Authentication

The default scheme is a policy scheme, `CaAuthentication`, that forwards to **JWT bearer** when the
request carries a `Bearer` token and to the **client-certificate** scheme otherwise. So a request
authenticated by mTLS (an EST client certificate) and a request authenticated by an operator JWT
both reach the CA endpoints; `/health` is open.

### Relational storage

The relational engine (postgres or mssql) is chosen by `Appliance:Engine`, so the same host binary
can target either backend; the per-engine image is selected at deploy time via the `.postgres` /
`.mssql` Dockerfiles. The store is wired only when `Ca:Persistence=relational`; otherwise the
in-memory store is the fallback.

> **Out-of-band migration.** The host never runs EF Core migrations at start-up. Provision the
> schema once (`dotnet ef database update` against the same connection string and engine) before the
> first request — exactly as the relational IQ test does with `RelationalTestDatabase`, which
> migrates the schema before the appliance container is started. See
> [`docs/docker.md`](../../../docs/docker.md#host-projects-per-role).

## Build and run

Each role publishes its own host binary; the per-engine Dockerfiles COPY that publish. The Cake
task `Appliance-Docker-Build` builds every role image, tagging each with `:latest` and the build
version:

```sh
# publish the CA host (invariant for the chiseled base/postgres variants)
dotnet publish src/hosts/opencertserver.host.ca -c Release -r linux-x64 \
    -p:InvariantGlobalization=true -o artifacts/publish/ca/linux-x64

# build the CA images (base + postgres + mssql), tagged :latest and :<version>
dotnet run --project build/opencertserver.build -c Release -- --target=Appliance-Docker-Build
```

The images run as the unprivileged UID `1654`. See [`docs/docker.md`](../../../docs/docker.md) and
[`docs/appliance.md`](../../../docs/appliance.md) for the full image catalog and the hardening
guarantees the IQ tests assert.

## Tests

The CA host is verified by the `CA appliance` scenario in
[`tests/opencertserver.iq.tests/Features/ApplianceContainers.feature`](../../../tests/opencertserver.iq.tests/Features/ApplianceContainers.feature),
which boots the image in a Linux container (via Testcontainers) and asserts the unprivileged user,
the TLS 1.3 handshake, the TLS 1.2 rejection, the omitted `Server` header, the healthy `/health`,
and that the CA responder is exposed while the EST, ACME, and SCEP endpoints are hidden.
