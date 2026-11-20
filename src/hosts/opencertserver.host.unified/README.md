# opencertserver.host.unified

The **superset** appliance host: it serves EST, ACME, SCEP, the CA responder, and `/health` from a
single process — the minimal surface that replaces the former
`opencertserver.certserver` monolith for the Unified role. It is one of the three per-role appliance
hosts under `src/hosts/`; the
[`opencertserver.host.ca`](../opencertserver.host.ca/README.md) and
[`opencertserver.host.ra`](../opencertserver.host.ra/README.md) hosts are the role-reduced variants
that omit the surfaces they do not serve.

Splitting the monolith into per-role hosts means the role that ships in an image compiles only the
middleware it serves, which shrinks the attack surface and the binary. The Unified host keeps every
surface; the CA and RA hosts drop the ones they do not need. See
[`docs/docker.md`](../../../docs/docker.md#host-projects-per-role) for the role→surface→reference
table.

## What runs here

`Program.Main` first handles two appliance subcommands — `configdump` and `configload`
(`ApplianceConfiguration.RunCommand`) — that migrate a mounted appliance configuration between
versions. Otherwise it builds the web host. The role is selected at start-up from
`Appliance:Role`:

- **`Ra`** — the process hands off to `RaApplianceHost.Run` (the RA surface only) and returns, so the
  same image can serve as an RA. The RA configuration contract is documented in
  [`opencertserver.host.ra`](../opencertserver.host.ra/README.md).
- **`Unified`** (default) — the full enrollment front-end.
- **`Ca`** — the ACME/EST enrollment endpoints are skipped (`hasEnrollment` is false), so the CA
  responder is the main surface. SCEP still maps unless `Scep:Enabled=false`; set that to run a
  CA-only surface like the standalone
  [`opencertserver.host.ca`](../opencertserver.host.ca/README.md). This sub-role exists so the
  combined image can also serve as a CA.

For the enrollment surface (`Unified`), the middleware maps, in order:

- **ACME** — `app.UseAcmeServer()` (only when the role has enrollment).
- **EST** — `app.UseEstServer(...)` with the enrollment policies (`enroll`, `reEnroll`,
  `serverKeyGen`), again only when the role has enrollment.
- **CA responder** — `app.UseCertificateAuthorityServer()` (always): the `/ca` route group
  (`/ca/csr`, `/ca/profiles`, `/ca/revoke`, `/ca/crl`, `/ca/published`, `/ca/ocsp`).
- **SCEP** — `app.MapScepServer()` (only when SCEP is enabled — see below), plus the Intune
  revocation sync `app.MapIntuneSync()` when Intune validation is configured.
- **`/health`** — always open.

## Role gating

`ApplianceOptions.Read` validates the role and the hardening contract. It throws unless `Appliance:Role`
is one of `Unified`, `Ca`, or `Ra`, and — when `Appliance:Hardened` is true — enforces:

- explicit `AllowedHosts` (no `*`),
- persistent CA keys (a hardened host forbids `dn`),
- `Appliance:DataDirectory` on persistent storage for the `Ca`/`Unified` roles,
- CAA checks on, external-account binding on, and both ACME hosted workers enabled for `Unified`,
- HTTPS-only Kestrel listeners.

## Configuration

Configuration is read from a mounted JSON document (`ApplianceConfiguration.AddMountedConfiguration`,
upgraded by `MigrationRunner`), environment variables, and command-line arguments. The keys that
matter for this host:

| Key | Meaning |
|---|---|
| `Appliance:Hardened` | When true (the default) the host is TLS 1.3-only, omits the `Server` header, strips the `X-Client-Cert` header, and audits every request. |
| `Appliance:Role` | `Unified` (default), `Ca`, or `Ra`. |
| `Appliance:DataDirectory` | The persistent directory for the appliance store (mounted read-write). A hardened CA/Unified requires it. |
| `Ca:Persistence` | `memory` (default) or `relational`. |
| `Appliance:Engine` | Selects the relational engine when `Ca:Persistence=relational`: `postgres` (default) or `mssql`. |
| `ConnectionStrings:OpenCertServer` | The relational connection string. |
| `dn` / `rsa:…` / `ecdsa:…` | CA profiles and their trust anchors; `dn` creates a self-signed CA at start-up (forbidden when hardened). |
| `Scep:Enabled` | Gates `MapScepServer`; off for the CA-only surface. |
| `AcmeServer:DisableCaaChecks`, `AcmeServer:ExternalAccountRequired`, `AcmeServer:HostedWorkers:*` | The ACME hardening toggles; a hardened Unified requires all of them on. |
| `Jwt:Authority` / `Jwt:Audiences` | The operator/EST identity provider. |
| `Kestrel:Endpoints:*` / `port` | The HTTPS listener(s). A hardened host permits only HTTPS. |

### SCEP surface

`IsScepEnabled` decides whether `MapScepServer` runs. The monolith enables SCEP by default, so a
fresh Unified maps `/scep` exactly as before; a CA-only host sets `Scep:Enabled=false` to run
`/ca/*` with no `/scep`. The Intune revocation sync (`MapIntuneSync`) maps only when the Intune
validation section exists.

### Relational storage

The relational engine (postgres or mssql) is chosen by `Appliance:Engine`, so the same host binary
can target either backend; the per-engine image is selected at deploy time via the `.postgres` /
`.mssql` Dockerfiles. The store is wired only when `Ca:Persistence=relational`; otherwise the
appliance store (when a `DataDirectory` is mounted) or the in-memory store is used.

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
# publish the Unified host (invariant for the chiseled base/postgres variants)
dotnet publish src/hosts/opencertserver.host.unified -c Release -r linux-x64 \
    -p:InvariantGlobalization=true -o artifacts/publish/unified/linux-x64

# build the Unified images (base + postgres + mssql), tagged :latest and :<version>
dotnet run --project build/opencertserver.build -c Release -- --target=Appliance-Docker-Build
```

`Dockerfile.appliance` is a compatibility build name for `Dockerfile.unified`; it produces the same
image. The images run as the unprivileged UID `1654`. See
[`docs/docker.md`](../../../docs/docker.md) and [`docs/appliance.md`](../../../docs/appliance.md) for
the full image catalog and the hardening guarantees the IQ tests assert.

## Tests

The Unified host is verified by the `Unified appliance` scenario and the relational `Unified`
outlines in
[`tests/opencertserver.iq.tests/Features/ApplianceContainers.feature`](../../../tests/opencertserver.iq.tests/Features/ApplianceContainers.feature),
which boot the image in a Linux container (via Testcontainers) and assert the unprivileged user, the
TLS 1.3 handshake, the TLS 1.2 rejection, the omitted `Server` header, the healthy `/health`, and —
for the relational outlines — that the appliance connects to and seeds its PostgreSQL and MSSQL
databases.
