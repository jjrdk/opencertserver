# Docker

The repository ships two Dockerfile families:

* **The published server image** — `Dockerfile` builds `jjrdk/opencertserver` over a
  `dotnet/runtime-deps` base with a self-contained, `Hardened`-profile server.
* **The headless appliance family** — `Dockerfile.unified`, `Dockerfile.ca`, `Dockerfile.ra`
  (plus `Dockerfile.appliance`, a compatibility alias for `Dockerfile.unified`) and their relational
  engine variants `Dockerfile.<role>.postgres` / `Dockerfile.<role>.mssql`. These ship a self-contained
  server on a chiseled Ubuntu 24.04 base as the unprivileged `app` user (UID `1654`).

For role-specific trust, endpoint, backup, and upgrade detail see the
[headless appliance operator guide](appliance.md).

## Host projects (per-role)

Each appliance role is a separate host project under `src/hosts/`, so the role that ships in an image
only compiles the middleware it serves:

| Host project | Role | Serves | References |
|---|---|---|---|
| `opencertserver.host.ca` | CA | `UseCertificateAuthorityServer` + `/health` (trust anchor: `/ca/csr`, `/ca/crl`, `/ca/ocsp`, `/ca/profiles`) | `ca.server`, `ca.utils`, `est.server` |
| `opencertserver.host.ra` | RA | `/ra/enroll`, `/ra/renew`, `/ra/revoke`, `/health` | `ra`, `est.server` |
| `opencertserver.host.unified` | Unified | EST + ACME + SCEP + CA + `/health` | superset of the above (+ `acme.server`, `acme.remote`, `scep.server`, `contrib.intune`) |

Each host ships a per-host runbook (`README.md`) documenting why it exists, what it serves/omits, and its
full configuration contract:

| Host | README |
|---|---|
| CA | [`src/hosts/opencertserver.host.ca/README.md`](../src/hosts/opencertserver.host.ca/README.md) |
| RA | [`src/hosts/opencertserver.host.ra/README.md`](../src/hosts/opencertserver.host.ra/README.md) |
| Unified / superset | [`src/hosts/opencertserver.host.unified/README.md`](../src/hosts/opencertserver.host.unified/README.md) |

The **relational engine** (postgres or mssql) is *not* a separate host: the same per-role host wires the
store from `Appliance:Engine` at start-up, and the per-engine image is selected at deploy time via the
`Appliance:<role>.<Engine>` environment variables baked into the `.postgres` / `.mssql` Dockerfiles. The
original `src/opencertserver.certserver` monolith is retained for the published server image and as the
compatibility reference; the host projects are the minimal per-role surfaces.

Relational storage requires a **schema that is created out of band**: the host never runs EF Core
migrations at start-up (it connects to an already-provisioned database). Provision the schema once —
`dotnet ef database update` against the same connection string and engine — before the first request,
exactly as the relational IQ test does with `RelationalTestDatabase` (which migrates the schema before the
appliance container is started).

## Image catalog

| Dockerfile | Role / surface | Base image | Engine | Ports |
|---|---|---|---|---|
| `Dockerfile` | Server (EST + ACME + SCEP + CA) | `runtime-deps:10.0-alpine` (musl) | — | 6000, 6001 |
| `Dockerfile.appliance` | Unified (alias of `Dockerfile.unified`) | `runtime-deps:10.0-noble-chiseled` | — (file store) | 6000, 6001 |
| `Dockerfile.unified` | Unified: EST, ACME, SCEP, CA, `/health` | `runtime-deps:10.0-noble-chiseled` | — (file store) | 6000, 6001 |
| `Dockerfile.ca` | CA responder + `/health` | `runtime-deps:10.0-noble-chiseled` | — (file store) | 6001 |
| `Dockerfile.ra` | RA operator API + `/health` | `runtime-deps:10.0-noble-chiseled` | — (file store) | 6001 |
| `Dockerfile.unified.postgres` | Unified, PostgreSQL store | `runtime-deps:10.0-noble-chiseled` | `postgres` | 6000, 6001 |
| `Dockerfile.ca.postgres` | CA, PostgreSQL store | `runtime-deps:10.0-noble-chiseled` | `postgres` | 6001 |
| `Dockerfile.ra.postgres` | RA, PostgreSQL store | `runtime-deps:10.0-noble-chiseled` | `postgres` | 6001 |
| `Dockerfile.unified.mssql` | Unified, MSSQL store | `runtime-deps:10.0-noble` (full, ICU) | `mssql` | 6000, 6001 |
| `Dockerfile.ca.mssql` | CA, MSSQL store | `runtime-deps:10.0-noble` (full, ICU) | `mssql` | 6001 |
| `Dockerfile.ra.mssql` | RA, MSSQL store | `runtime-deps:10.0-noble` (full, ICU) | `mssql` | 6001 |

`Dockerfile.appliance` is a compatibility build name for `Dockerfile.unified`; it produces the same
image.

## The published server image (`Dockerfile`)

```dockerfile
ARG PLATFORM=linux/amd64
FROM --platform=${PLATFORM} mcr.microsoft.com/dotnet/runtime-deps:10.0-alpine
ARG RID=linux-musl-x64
ENV ACCEPT_EULA=Y
ENV ASPNETCORE_ENVIRONMENT=Hardened          # embeds CDP/AIA/OCSP URLs, EAB, OTLP, attestation
RUN addgroup -S certificateservergroup \
  && adduser -S certificateserveruser -G certificateservergroup \
  && mkdir -p /var/lib/opencertserver \
  && chown certificateserveruser:certificateservergroup /var/lib/opencertserver
USER certificateserveruser
COPY artifacts/publish/server/${RID}/ app/
WORKDIR /app
EXPOSE 6000 6001
VOLUME ["/var/lib/opencertserver"]
ENTRYPOINT ["./opencertserver.certserver"]
```

The `Hardened` profile is the default in the published image: it embeds the CDP / AIA / OCSP responder
URLs, enables external account binding and OpenTelemetry export over OTLP, and enforces the
`device-attest-01` fail-closed posture when no trust roots are mounted.

## The appliance family

The appliance Dockerfiles build on the **chiseled** `runtime-deps` image
(`mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled`), which carries the glibc native runtime
dependencies (including OpenSSL 3, which .NET's `SslStream` loads) but no .NET runtime — and no chiseled
ASP.NET Core image exists. The application is therefore published **self-contained** with the glibc RID
(`linux-x64` / `linux-arm64`); the publish bundles coreclr, hostfxr, and the ASP.NET Core framework on
top of the glibc dependencies.

Two hardening postures are baked into every appliance image:

* **Unprivileged process** — the image runs as `app` (UID `1654`); no root tooling is added.
* **TLS 1.3 only + HTTPS-only** — `Appliance__Hardened=true` enforces TLS 1.3 and refuses to start on a
  plain-HTTP listener.
* **Invariant globalization** — the chiseled image ships no ICU, so the runtime is configured for
  invariant globalization: the publish sets `-p:InvariantGlobalization=true` and the Dockerfile exports
  `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`.

Each base variant bakes its role:

```dockerfile
ENV Appliance__Role=Unified     # | Ca | Ra
ENV Appliance__Hardened=true
ENV Telemetry__Enabled=false
```

`PLATFORM` and `RID` default to `linux/amd64` / `linux-x64`; the IQ test harness overrides both to run
the image natively on the Docker host's architecture.

### Relational backend (engine variants)

For a relational backend instead of the in-container file store, use the matching engine variant
(`Dockerfile.<role>.postgres` or `Dockerfile.<role>.mssql`). It bakes three additional environment
defaults:

```dockerfile
ENV Appliance__Engine=postgres          # postgres | mssql — selects the IRelationalStoreProvider
ENV AcmeServer__Persistence=relational  # selects the relational ACME stores
ENV Ca__Persistence=relational          # selects the relational certificate store
```

The connection string is **not** baked in; it is a deployment secret supplied at runtime via the
`ConnectionStrings:OpenCertServer` environment variable (`ConnectionStrings__OpenCertServer`). The
`OpencertServer` connection-string name is shared by the ACME and CA stores, so a single entry backs
both.

The **postgres** variants are chiseled and invariant (Npgsql tolerates invariant mode). The **mssql**
variants are not: the SQL Server EF Core provider (`Microsoft.Data.SqlClient`, via
`RelationalConnection`) hard-requires ICU, which the chiseled image does not ship. The mssql variant
therefore builds on the **full** `mcr.microsoft.com/dotnet/runtime-deps:10.0-noble` base (which carries
ICU) from a **non-invariant** self-contained publish, and omits
`DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`. The hardened posture (UID `1654`, TLS 1.3, HTTPS-only) is
unchanged; the image is simply larger because ICU and the full locale data ship in it.

**Migrations are out of band.** The appliance never applies schema migrations at startup; the relational
store assumes the schema already exists. Apply it once, before starting or upgrading the server:

```sh
# PostgreSQL
dotnet ef database update --project src/opencertserver.data.postgresql
# MSSQL
dotnet ef database update --project src/opencertserver.data.mssql
```

Back up the database before an upgrade and generate and review an idempotent migration script for
production. See the [operator guide's relational-storage section](appliance.md#relational-storage).

## Build

The published image is built by the Cake `Linux-Docker-Build` task
(`build/opencertserver.build/LinuxDockerBuildTask.cs`), which publishes
`src/opencertserver.certserver` to `artifacts/publish/server/linux-musl-x64` and builds the root
`Dockerfile` with tags `jjrdk/opencertserver:latest` and `jjrdk/opencertserver:<version>`.

The appliance images are built by the Cake `Appliance-Docker-Build` task
(`build/opencertserver.build/ApplianceDockerBuildTask.cs`), which publishes **each role's own host
project** to `artifacts/publish/<role>/linux-x64/` (base + postgres, `InvariantGlobalization=true`) and
to `artifacts/publish/<role>/mssql/linux-x64/` (mssql, no `InvariantGlobalization` — ICU required), then
builds every `Dockerfile.{appliance,unified,ca,ra}` and `Dockerfile.{unified,ca,ra}.{postgres,mssql}`.
Each image is tagged with the same version tag the rest of the build uses (`<image>:latest` and
`<image>:<version>`), e.g. `opencertserver-appliance-ca:<version>`. Run it with:

```sh
dotnet run --project build/opencertserver.build/opencertserver.build.csproj -c Release -- --target=Appliance-Docker-Build
```

You can also build them by hand: each appliance Dockerfile copies the self-contained publish of its own
host project from `artifacts/publish/<role>/${RID}/` (mssql from
`artifacts/publish/<role>/mssql/${RID}/`). Stage that publish first, then build from the repository root
as the build context:

```sh
# Stage the per-role publish (example: CA, base + postgres)
dotnet publish src/hosts/opencertserver.host.ca -c Release -r linux-x64 \
  -p:SelfContained=true -p:PublishTrimmed=false -p:InvariantGlobalization=true \
  --artifacts-path artifacts/publish/ca
# Unified (file store)
docker build -f Dockerfile.unified -t opencertserver-appliance-unified:local .
# CA / RA
docker build -f Dockerfile.ca -t opencertserver-appliance-ca:local .
docker build -f Dockerfile.ra -t opencertserver-appliance-ra:local .
# Relational
docker build -f Dockerfile.unified.postgres -t opencertserver-appliance-unified-postgres:local .
docker build -f Dockerfile.unified.mssql   -t opencertserver-appliance-unified-mssql:local .
```

Build from the repository root (the Dockerfiles reference `artifacts/publish/...` relative to the
context). Pin the published image by immutable digest rather than a mutable tag, and use the same
version-pinned application release for the CA and RA.

## Run

Place the role's JSON at `config/appsettings.json` and the TLS/CA key material it references under
`keys/`, then mount the config at `/config/appsettings.json` and the keys at the path the config
expects (the `deploy/appliance/*.json` examples reference `/run/secrets/...`). Ensure the mounted files
are readable by UID `1654`; never bake private keys or secrets into the image or a versioned config.

The listening port is the config's `port` field (Kestrel binds `https://*:{port}`; the image's
`EXPOSE` are nominal defaults), so publish that port:

```sh
docker run -d --name opencertserver-unified --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -p 5001:5001 \
  -e AllowedHosts="pki.example.com;localhost" \
  --mount type=bind,src="$PWD/config/appsettings.json",dst=/config/appsettings.json,readonly \
  --mount type=bind,src="$PWD/keys",dst=/run/secrets,readonly \
  opencertserver-unified:local
```

For a CA or Unified role that persists state, add a data volume the operator owns (UID `1654`),
e.g. `--mount type=volume,src=opencertserver-data,dst=/var/lib/opencertserver`. The RA role holds no
issuing CA state, so it needs no data volume. Because the appliance runs unprivileged (UID `1654`), a
root-owned volume is not writable — use an operator-owned directory. The CA and RA roles configure
`port` `5001`; Unified does too in the supplied example, with the listener bound by the config.

### Relational appliance

Supply the connection string at runtime via `ConnectionStrings__OpenCertServer` (the database must
already be migrated — see [Relational backend](#relational-backend-engine-variants)):

```sh
docker run -d --name opencertserver-unified-postgres --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -p 5001:5001 \
  -e AllowedHosts="pki.example.com;localhost" \
  -e 'ConnectionStrings__OpenCertServer=Host=db;Port=5432;Database=opencert;Username=ocs;Password=REPLACE_WITH_SECRET' \
  --mount type=bind,src="$PWD/config/appsettings.json",dst=/config/appsettings.json,readonly \
  --mount type=bind,src="$PWD/keys",dst=/run/secrets,readonly \
  opencertserver-unified-postgres:local
```

For MSSQL, use `Dockerfile.unified.mssql` and an MSSQL connection string. Start the MSSQL database
container with `ACCEPT_EULA=Y`; the mssql image trusts the server certificate on the test network, so
pin a real CA in production.

## Kubernetes

Mount the configuration and CA keys, and pass the runtime secrets as a `ConfigMap` and `Secret`.
The config's `port` selects the listener; expose that port on the `Service`:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: opencertserver-config
data:
  appsettings.json: |
    { "version": 2, "port": 5001, "AllowedHosts": "pki.example.com" }
---
apiVersion: v1
kind: Secret
metadata:
  name: opencertserver-keys
type: Opaque
stringData:
  rsa-ca.pem: "-----BEGIN CERTIFICATE-----\n<CA CERTIFICATE>\n-----END CERTIFICATE-----\n"
  rsa-ca.key: "-----BEGIN PRIVATE KEY-----\n<CA PRIVATE KEY>\n-----END PRIVATE KEY-----\n"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: opencertserver
spec:
  replicas: 1
  selector:
    matchLabels:
      app: opencertserver
  template:
    metadata:
      labels:
        app: opencertserver
    spec:
      containers:
        - name: opencertserver
          image: jjrdk/opencertserver:latest
          securityContext:
            runAsUser: 1654
            runAsGroup: 1654
            fsGroup: 1654
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: ["ALL"]
          ports:
            - containerPort: 5001
          env:
            - name: OPENCERT_CONFIG
              value: /config/appsettings.json
          volumeMounts:
            - name: config
              mountPath: /config
              readOnly: true
            - name: keys
              mountPath: /run/secrets
      volumes:
        - name: config
          configMap:
            name: opencertserver-config
        - name: keys
          secret:
            secretName: opencertserver-keys
```

## Verification

`opencertserver.iq.tests` `ApplianceContainers.feature` boots each appliance image against a
Testcontainers-managed database and proves the hardened posture and role surface from a separate client
container: the Unified, CA, and RA images run as UID `1654`, complete a TLS 1.3 handshake, reject TLS
1.2, omit the `Server` header, report a healthy `/health`, and expose only their own endpoint surface.
A hardened appliance refuses to start when a plain-HTTP listener is absent. The relational scenarios
(`Unified|postgres` and `Unified|mssql`) boot the engine-variant image against a Testcontainers
PostgreSQL or MSSQL container and prove it connects to and seeds the database. See the
[operator guide's verification section](appliance.md#verification).
