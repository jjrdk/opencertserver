# Headless appliance operator guide

This guide covers the source-built, chiseled Ubuntu 24.04 container images and the host
configuration they consume. The appliance is headless and provides protocol endpoints and APIs.

## Roles and images

| Image | Service surface | Local CA keys | Typical use |
|---|---|---:|---|
| `opencertserver-unified` (`Dockerfile.unified`) | CA `/ca/*`, EST, ACME, SCEP, `/health` | Yes | Single-host CA and enrollment protocols |
| `opencertserver-ca` (`Dockerfile.ca`) | Existing `/ca/*` endpoints and `/health` only | Yes | CA backend for a separate RA service |
| `opencertserver-ra` (`Dockerfile.ra`) | Operator API `/ra/*` and liveness `/health` | No | Authenticated RA service delegating issuance to a CA |
| `Dockerfile.appliance` | Same unified role as `Dockerfile.unified` | Yes | Compatibility build name for the unified image |

The in-container, file-backed store is the default for every role above. For a
relational backend, build the matching engine variant instead —
[`Dockerfile.<role>.postgres`](#relational-storage) /
[`Dockerfile.<role>.mssql`](#relational-storage) — which bakes the engine selector and the
`relational` persistence choices and reads its connection string from the environment at runtime.

The RA image is not the `opencertserver.ra` library by itself. It is the headless RA host
which uses that library's outbound `RaPeerClient`. It does not expose EST, ACME, the CA's
`/ca/*` routes, or an inbound CA peer API. The CA and RA communicate over the RA client's
outbound HTTPS connection.

Build from the repository root:

```sh
docker build -f Dockerfile.unified -t opencertserver-unified:local .
docker build -f Dockerfile.ca -t opencertserver-ca:local .
docker build -f Dockerfile.ra -t opencertserver-ra:local .
```

Use the same version-pinned application release for the CA and RA. In production, pin the
published image by immutable digest rather than a mutable tag. All appliance images are
chiseled Ubuntu 24.04 (Noble) for .NET 10, run as non-root UID `1654`, and enforce TLS 1.3.

The appliance Dockerfiles build on the chiseled `runtime-deps` image
(`mcr.microsoft.com/dotnet/runtime-deps:10.0-noble-chiseled`), which carries the glibc native
runtime dependencies (including OpenSSL 3, which .NET's `SslStream` loads) but no .NET runtime —
and no chiseled ASP.NET Core image exists. The application is therefore published
**self-contained** with the glibc RID (`linux-x64` / `linux-arm64`) and
`InvariantGlobalization=true`; the publish bundles coreclr, hostfxr and the ASP.NET Core framework
on top of the glibc dependencies. The chiseled base already runs as the unprivileged `app` user
(UID `1654`), so the images add no root tooling.
Because the image ships no ICU, the runtime is configured for invariant globalization; the
self-contained publish sets this via `-p:InvariantGlobalization=true` and the Dockerfiles export
`DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`.

## Files and configuration

Each image reads the selected JSON configuration from `OPENCERT_CONFIG`, defaulting to
`/config/appsettings.json`. Mount this file read-only. A missing file, unsupported schema
version, or invalid configuration prevents startup. The supplied examples are:

* [Unified CA + EST + ACME](../deploy/appliance/unified.json)
* [CA-only service](../deploy/appliance/ca.json)
* [RA service](../deploy/appliance/ra.json)

The top-level `version` must be `2`. Configuration precedence is defaults, environment-
specific settings, the selected mounted file, environment variables, then command-line
arguments; higher-precedence settings override lower-precedence values. `OPENCERT_CONFIG`
selects the mounted file. For example, `Jwt__Authority` overrides `Jwt:Authority`.
Restart the container after changing configuration; these settings are not hot-reloaded.

The role is selected by the image and is not changed by the mounted JSON. Configure
`AllowedHosts` with accepted DNS hostnames (semicolon-separated, no ports), including the
Host header used by health probes. Do not use `*` in production.

### Unified and CA-only configuration

Unified and CA-only instances need persistent CA certificate and private-key files referenced
by their configuration. The TLS listener certificate is a separate keypair. Mount all key
and certificate files read-only, with permissions that allow UID 1654 to read them.

Set `CaServer:OCSP` and `CaServer:CrlDistributionPoints` to the actual externally reachable
URLs, including the published port. Hardened defaults do not advertise placeholder
revocation, issuer-certificate, or terms-of-service URLs. Provision EAB credentials under
`AcmeServer:ExternalAccountKey` from your secret source before accepting ACME accounts.
If terms agreement is required, configure `AcmeServer:TOS:RequireAgreement`, `Url`, and
`LastUpdate` with your own published terms.

For a CA that accepts delegated RA requests, explicitly enable acceptance and bind the RA
identity to the permitted DNS suffix and profiles. The RA ID is the common name (`CN`) of
the CA-issued client certificate used by the RA:

```json
{
  "Ca": {
    "AcceptRa": true,
    "RaBindings": [
      {
        "RaId": "ra-tenant-a",
        "Scopes": ["tenant-a.example.com"],
        "Profiles": ["rsa"]
      }
    ]
  }
}
```

Keep the profile names consistent with the CA's configured profiles and the RA's
`Ra:Profile`. Bind only the DNS suffixes and profiles that the RA is authorized to use.
Acceptance is disabled unless `Ca:AcceptRa` is true.

### RA configuration and authentication

The RA service requires a valid HTTPS identity provider in `Jwt:Authority` and one or more
`Jwt:Audiences`. Every `/ra/*` operation requires a bearer token with the `ra_operator` role.
Configure the backend peer with:

| Setting | Requirement |
|---|---|
| `Ra:PeerUrl` | Absolute HTTPS URL of the CA peer endpoint |
| `Ra:Scope` | Delegated DNS suffix configured in a CA `RaBindings` entry |
| `Ra:Profile` | CA profile name permitted by that binding (for example `rsa`) |
| `Ra:ClientCertificatePath` | Path to the CA-issued RA client certificate in PEM format |
| `Ra:ClientPrivateKeyPath` | Path to its corresponding private key in PEM format |
| `Ra:CaTrustRoots` | Optional array of PEM CA root certificate file paths used to validate the peer |
| `Ra:BearerToken` | Optional bearer token for the outbound peer, if required by the CA configuration |

Mount the RA certificate and key read-only as secrets. The RA sends a fresh CSR for both
enrollment and renewal; renewal is a new enrollment under the delegated scope, not EST
re-enrollment authenticated by the original certificate. The peer validates the CA server's
certificate using normal TLS hostname and validity checks, EKU checks, and either system
trust or the configured custom root set. HTTP redirects are disabled. Transport certificate
revocation checking is not enabled by the default `HttpClientHandler`.

The CA validates the RA's mTLS client certificate with online revocation checking by default.
Its CRL/OCSP distribution points must therefore be reachable from the CA container. Provision
the RA identity with working revocation infrastructure; do not disable revocation validation as
a workaround.

The CA must issue the RA client certificate and configure a matching `RaId` binding. The
RA's operator JWT identity is separate from this backend mTLS identity. Do not confuse the
public API token with the RA-to-CA client certificate.

## Endpoints

The RA API uses HTTPS. Its liveness endpoint is `GET /health`; it confirms that the RA host
is alive and does **not** check reachability or health of the CA peer.

| Method and path | Request | Result |
|---|---|---|
| `POST /ra/enroll` | PEM-encoded PKCS#10 CSR in the request body | Requests a certificate within the configured RA scope and profile |
| `POST /ra/renew` | PEM-encoded replacement PKCS#10 CSR in the request body | Performs a fresh enrollment under the same scope and profile |
| `DELETE /ra/revoke?sn=<serial>&reason=<name>` | Hex certificate serial and an `X509RevocationReason` enum name | `204` when processed; `404` when no matching issued certificate is found |

All three `/ra` operations require a JWT bearer token with the `ra_operator` role. Scope and
profile authorization is enforced by the CA peer. For revocation, `reason` is the enum name,
not a numeric value. Do not assume the liveness probe tests CA connectivity; monitor the
backend separately.

Example requests (replace the hostname, root, token, and CSR path):

```sh
curl --cacert tls-root.pem \
  -H "Authorization: Bearer $RA_OPERATOR_TOKEN" \
  --data-binary @request.csr.pem \
  https://ra.example.com:5001/ra/enroll

curl --cacert tls-root.pem \
  -H "Authorization: Bearer $RA_OPERATOR_TOKEN" \
  --data-binary @replacement.csr.pem \
  https://ra.example.com:5001/ra/renew

curl --cacert tls-root.pem \
  -H "Authorization: Bearer $RA_OPERATOR_TOKEN" \
  -X DELETE \
  "https://ra.example.com:5001/ra/revoke?sn=0123ABCD&reason=Unspecified"
```

## Running containers

Prepare host directories for `config/` and `keys/`, place the role's JSON file at
`config/appsettings.json`, and put referenced TLS and CA key material under `keys/`.
Ensure the mounted files are readable by UID 1654. Never bake private keys, bearer tokens,
or identity-provider secrets into an image or source-controlled configuration.

Create persistent state for a CA or unified role:

```sh
docker volume create opencertserver-data
```

Example unified deployment:

```sh
docker run -d --name opencertserver-unified --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -p 5001:5001 \
  --mount type=bind,src="$PWD/config/appsettings.json",dst=/config/appsettings.json,readonly \
  --mount type=bind,src="$PWD/keys",dst=/run/secrets,readonly \
  --mount type=volume,src=opencertserver-data,dst=/var/lib/opencertserver \
  opencertserver-unified:local
```

For the CA-only image, use the same command with the CA configuration and image name
`opencertserver-ca:local`. For the RA image, use `deploy/appliance/ra.json`, mount the RA
client certificate/key and any custom trust roots, and omit the state volume because the RA
does not hold issuing CA state:

```sh
docker run -d --name opencertserver-ra --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -p 5001:5001 \
  --mount type=bind,src="$PWD/config/appsettings.json",dst=/config/appsettings.json,readonly \
  --mount type=bind,src="$PWD/keys",dst=/run/secrets,readonly \
  opencertserver-ra:local
```

Restrict inbound network access to the intended TLS port and operators. The appliance
terminates TLS itself; do not put it behind an HTTP redirect or expose a plaintext listener.
If a TLS-terminating proxy is required, configure that topology deliberately and preserve
host validation; direct TLS termination is the supported default. Health checks must connect
over HTTPS and send an allowed Host header, for example:

```sh
curl --cacert tls-root.pem \
  --resolve ra.example.com:5001:127.0.0.1 \
  https://ra.example.com:5001/health
```

Container request-audit events are written to stdout/stderr. Collect logs in access-controlled
durable storage and set retention appropriate to your policy.

## Relational storage

The default appliance store is in-container (a tmpfs `certificates.json` snapshot plus the ACME
file store for the Unified role). A relational backend (PostgreSQL or MSSQL) is selected by an
**engine variant Dockerfile** and its connection string is supplied at **runtime** — it is never
baked into the image.

### Engine variants

Each role has two relational variants alongside its base image:

| Base image | Relational variants |
|---|---|
| `Dockerfile.unified` | `Dockerfile.unified.postgres`, `Dockerfile.unified.mssql` |
| `Dockerfile.ca` | `Dockerfile.ca.postgres`, `Dockerfile.ca.mssql` |
| `Dockerfile.ra` | `Dockerfile.ra.postgres`, `Dockerfile.ra.mssql` |

Each variant bakes the same three environment defaults as its base:

```dockerfile
ENV Appliance__Engine=postgres          # postgres | mssql — selects the IRelationalStoreProvider
ENV AcmeServer__Persistence=relational  # selects the relational ACME stores
ENV Ca__Persistence=relational          # selects the relational certificate store
```

The connection string is **not** baked in; it is a deployment secret supplied at runtime via the
`ConnectionStrings:OpenCertServer` environment variable (`ConnectionStrings__OpenCertServer`). The
RA role does not issue and has no data directory, so its relational variants are inert (its store
selection has nothing to write) — use a relational backend on the Unified or CA roles.

The **postgres** variants are chiseled like their base image. The **mssql** variants are not: the
SQL Server EF Core provider (`Microsoft.Data.SqlClient`, via `RelationalConnection`) hard-requires ICU,
which the chiseled `runtime-deps` image does not ship. The PostgreSQL provider (`Npgsql`) tolerates
invariant globalization, so the postgres variant can stay chiseled and invariant; the mssql variant
must instead build on the **full** `mcr.microsoft.com/dotnet/runtime-deps:10.0-noble` base (which
carries ICU) from a **non-invariant** self-contained publish — it keeps the same hardened posture
(UID 1654, TLS 1.3, HTTPS-only) but is larger because ICU and the full locale data ship in the image.
The mssql image therefore omits `DOTNET_SYSTEM_GLOBALIZATION_INVARIANT=1`.

Build from the repository root:

```sh
docker build -f Dockerfile.unified.postgres -t opencertserver-unified-postgres:local .
docker build -f Dockerfile.unified.mssql   -t opencertserver-unified-mssql:local .
```

### Migrations are out of band

The appliance **never** applies schema migrations at startup. The relational store assumes the
schema already exists. Apply it out of band with the matching adapter's EF migration project,
**once, before starting or upgrading the server** — the same procedure as the embedded-host
guidance in [Getting started](getting-started.md#postgresql-persistence):

```sh
# PostgreSQL
dotnet ef database update --project src/opencertserver.data.postgresql
# MSSQL
dotnet ef database update --project src/opencertserver.data.mssql
```

Back up the database before an upgrade; generate and review an idempotent migration script for
production. The `OpencertServer` connection-string name is shared by the ACME and CA stores, so a
single `ConnectionStrings:OpenCertServer` entry backs both.

### Running a relational appliance

```sh
docker run -d --name opencertserver-unified-postgres --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  -p 5001:5001 \
  -e 'ConnectionStrings__OpenCertServer=Host=db;Port=5432;Database=opencert;Username=ocs;Password=REPLACE_WITH_SECRET' \
  --mount type=bind,src="$PWD/config/appsettings.json",dst=/config/appsettings.json,readonly \
  --mount type=bind,src="$PWD/keys",dst=/run/secrets,readonly \
  opencertserver-unified-postgres:local
```

The database is reached over the network at `ConnectionStrings:OpenCertServer`; the engine variant
image determines which provider (PostgreSQL or MSSQL) and store implementation are registered.
The MSSQL variant trusts the server certificate on the test network — pin a real CA in production.

### Verification

`opencertserver.iq.tests` `ApplianceContainers.feature` boots a relational appliance against a
Testcontainers-managed PostgreSQL or MSSQL container on a shared network and proves it connects and
seeds data: the out-of-band-migrated schema is prepared on the network first, then a black-box
`GET /new-nonce` (anonymous on a hardened Unified appliance) forces the appliance to persist a nonce
row, and the test queries the database directly to assert the row exists. The relational backend is
selected by the engine-baked image and reached via the runtime-supplied connection string — the same
mechanism a deployment uses to supply a database password.

## Container image verification

All four appliance Dockerfiles (`Dockerfile.appliance`, `Dockerfile.unified`, `Dockerfile.ca`,
and `Dockerfile.ra`) build chiseled Ubuntu 24.04 images successfully. Each publishes the
application self-contained over the glibc `runtime-deps` base (no .NET runtime is present on the
chiseled image), so the framework and coreclr ship in the publish output. The
[AOT qualification limits](standards.md#hardened-headless-appliance-t18) no longer apply —
self-contained trimming is not used, so the TPM/DnsClientX AOT warnings that native-AOT publish
reported do not occur.

`ApplianceUpgrade.feature` includes process-host scenarios and opt-in real Linux image checks.
Run the feature with:

```sh
dotnet test --project tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj \
  --filter-class '*HardenedAppliance*'
```

On Linux, process-host startup/configuration scenarios can run without Docker image variables.
On macOS, the host `SslStream` does not support TLS 1.3, so image-backed startup scenarios are
skipped unless `OPENCERT_APPLIANCE_TEST_IMAGE` names a built Linux image. The topology scenario
is always image-gated and requires Docker and `curl`; process-host probes also use `curl`.
The chiseled base has no shell or `curl`, so black-box assertions (TLS posture, endpoint surface,
non-root user) are driven from a separate Ubuntu client container — see the
`opencertserver.iq.tests` appliance scenarios.
Build and select the images as follows:
the role-specific image variables are optional and otherwise fall back to the unified image:

```sh
docker build -f Dockerfile.appliance -t opencertserver-appliance:test .
docker build -f Dockerfile.unified -t opencertserver-unified:test .
docker build -f Dockerfile.ca -t opencertserver-ca:test .
docker build -f Dockerfile.ra -t opencertserver-ra:test .

OPENCERT_APPLIANCE_TEST_IMAGE=opencertserver-unified:test \
OPENCERT_APPLIANCE_TEST_CA_IMAGE=opencertserver-ca:test \
OPENCERT_APPLIANCE_TEST_RA_IMAGE=opencertserver-ra:test \
  dotnet test --project tests/opencertserver.certserver.tests/opencertserver.certserver.tests.csproj \
    --filter-class '*HardenedAppliance*'
```

The image-backed checks prove TLS 1.3 succeeds and TLS 1.2 fails, unified CA/EST/ACME exposure,
CA/RA route isolation, and unauthenticated RA operator requests return 401. Native ACME checks
reject a missing EAB, register a bound account, and reload the account, order and order list
from the file store. Aggregate round-trip checks preserve identities, challenge state and
parent references; concurrent file nonce consumption permits one successful consumer.
The CA+RA topology additionally uses a mock
OIDC issuer, a CA-issued RA mTLS identity with reachable CRL infrastructure, and a real
enrollment/revocation flow: it verifies the issued certificate against the CA root, rejects an
out-of-scope CSR, and confirms revocation succeeds. The test maps
`host.docker.internal` to the host gateway with Docker's
`--add-host host.docker.internal:host-gateway` option for the mock issuer and CRL endpoint;
the Docker engine must support that host-gateway mapping.

Health checks are liveness only; they do not prove that the CA peer is reachable. These
image-backed checks are separate from hardware-attestation/dynamic-TPM qualification, and
successful image builds do not qualify every dependency or hardware path for Native AOT.

## State, backups, upgrades, and rollback

`Appliance:DataDirectory` defaults to `/var/lib/opencertserver`. In the CA and unified roles
it contains the local certificate/revocation snapshot (`certificates.json`, schema version
1); the unified image also persists its ACME file store there. This is separate from the
mounted configuration schema version 2. Run only one CA writer against a state directory;
do not use rolling replicas that share a writable volume.

Before any upgrade, stop the service and create a consistent backup of the mounted
configuration, TLS identity, CA certificates and private keys, and the complete persistent
state volume. These items must be recoverable together. Treat backups and configuration
exports as secrets, encrypt and access-control them, and test restoration offline.

Pin and record the old image digest. Test the new digest against a copy of the configuration
and state before production. Configuration `configload <source> <new-destination>` upgrades
supported version 1 JSON files to version 2, grouping legacy `authority` and comma-separated
`audience` into `Jwt:Authority` and `Jwt:Audiences`. It refuses an existing destination and
creates owner-only output files on Unix. `configdump <source> <new-destination>` exports
current version 2 configuration; it refuses old-schema input rather than migrating it.
Neither command exports environment-variable overrides or private-key files. The JSON
configuration can itself contain secrets, so secure the output.

Run either command in the matching image with a read-only input mount and a separate writable
output mount. Prepare the host input and output directories so UID `1654` can read and write
them as needed. The tools refuse to overwrite existing files:

```sh
mkdir -p config/input config/output config/export
docker run --rm --user 1654:1654 \
  --mount type=bind,src="$PWD/config/input",dst=/input,readonly \
  --mount type=bind,src="$PWD/config/output",dst=/output \
  opencertserver-unified:local configload /input/v1.json /output/v2.json
docker run --rm --user 1654:1654 \
  --mount type=bind,src="$PWD/config/output",dst=/input,readonly \
  --mount type=bind,src="$PWD/config/export",dst=/output \
  opencertserver-unified:local configdump /input/v2.json /output/export.json
```

Alternatively, `Migration:AutoApply=true` opts into a supported older configuration upgrade
in memory at startup; it does not rewrite the read-only mounted file. Unknown and future
schema versions fail closed. This is configuration migration, not the roadmap's complete
T25 managed configuration dump/load and approval engine.

For rollback, stop the new container and restore the old image digest, configuration,
certificates/keys, and state from the same pre-upgrade backup. Do not point an older image
at state that a newer version has modified. Keep the failed-upgrade state separate for
investigation.

## Operational boundaries

* TLS 1.3 is enforced for all appliance roles. Hardened ACME worker, CAA, and EAB checks apply
  only to the Unified role; they do not imply ACME routes exist in Ca or Ra roles.
* Qualify TLS 1.3 and role isolation against the Linux images during container release testing.
  Process-host TLS tests may vary with the host TLS stack (including SecureTransport on macOS).
* The operational request audit is structured logging, not a tamper-evident audit chain.
* The appliance does not claim a hardware certification, a managed SaaS service, or a full
  database migration system.
* The RaPeerClient's transport validation checks certificate trust, hostname, validity, and
  EKU; the default transport does not perform certificate revocation checks.

See [Getting started](getting-started.md#appliance-roles-and-upgrades) for the developer
workflow, [Endpoint and configuration reference](documentation.md) for the full HTTP surface,
and [Implemented standards](standards.md#hardened-headless-appliance-t18) for the BDD evidence.
