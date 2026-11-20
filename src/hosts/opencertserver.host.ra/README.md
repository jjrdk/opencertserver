# opencertserver.host.ra

A hardened **registration-authority appliance**. Unlike
[`opencertserver.ra.server`](../../opencertserver.ra.server/README.md) — a plain RA front-end — this
host hardens the TLS/Kestrel surface and guards its RA operator endpoints with a role-checked JWT,
mirroring the central CA's RA role. Every issuance and revocation is delegated to a **backing
certificate authority** over a trusted HTTPS connection; the RA hosts policy and audit, **never the
CA core**.

This host is one of the three per-role appliance hosts under `src/hosts/`. Splitting the former
`opencertserver.certserver` monolith into per-role hosts means the role that ships in an image
compiles only the middleware it serves, which shrinks the attack surface and the binary. See
[`docs/docker.md`](../../../docs/docker.md#host-projects-per-role) for the role→surface→reference
table.

## What runs here

- **The RA operator API** — three endpoints, each guarded by the `ra_operator` authorization
  policy (a JWT with the `ra_operator` role):
  - `POST /ra/enroll` — enroll a PKCS#10 request; returns the signed chain as
    `application/pem-certificate-chain`. An optional `profile` query selects the CA profile,
    falling back to the CA's default.
  - `POST /ra/renew` — renew; same shape as enroll.
  - `DELETE /ra/revoke?sn=<serial>&reason=<X509RevocationReason>` — revoke by serial and reason
    name. A missing serial or an unknown reason is a 400; a peer rejection is surfaced as the peer's
    status (400/403/404) or a 502.
- **`/health`** — open, for liveness probes.
- **The RA peer client** — `AddRaPeerClient(RaPeerOptions.FromConfiguration(...))` registers the
  outbound `RaPeerClient` that delegates to the backing CA. The RA presents its own client
  certificate and validates the CA's chain against the operator-supplied trust roots
  (`Ra:CaTrustRoots`), rejecting a non-HTTPS peer.
- **EST to its own clients** — `AddEstServer<CsrTemplateLoader>()` registers the EST services and
  the built-in template loader so the RA can serve EST to its clients, issuing through the CA peer.

## What it intentionally omits

- **The CA core** — the RA references `opencertserver.ca.client`, `opencertserver.ra`,
  `opencertserver.ra.server`, and `opencertserver.est.server`, but **never**
  `opencertserver.ca` or `opencertserver.ca.server`. It hosts no CA key.
- **ACME** and **SCEP** — those surfaces belong to the
  [`opencertserver.host.unified`](../opencertserver.host.unified/README.md) host.
- **A relational store** — an RA delegates all state to the backing CA, so it keeps no
  `IStoreCertificates` of its own.

## Configuration

Configuration is read from the usual sources plus environment variables. Every key below is
**required**: the RA refuses to start without them, which is its operational contract.

| Key | Meaning |
|---|---|
| `Appliance:Hardened` | When true (the default) the host is TLS 1.3-only and audits every request. |
| `Jwt:Authority` | **Required.** The operator identity provider; must be an HTTPS URL. |
| `Jwt:Audiences` | **Required.** At least one audience for RA operator authentication. |
| `Ra:ClientCertificatePath` / `Ra:ClientPrivateKeyPath` | **Required.** The RA's client identity presented to the backing CA. |
| `Ra:PeerUrl` | **Required** via `RaPeerOptions.FromConfiguration`. The backing CA's HTTPS base URL; a non-HTTPS peer is rejected. (This is the CA endpoint — the host does not read a separate `Ra:Authority`.) |
| `Ra:Scope` | **Required.** The delegated DNS suffix for RA operations. |
| `Ra:Profile` / `Ra:Profiles` | The CA profile(s) the RA may use; empty means every profile the CA supports. |
| `Ra:CaTrustRoots` | The PEM trust roots the RA uses to validate the CA's chain. Each file must contain at least one certificate. |
| `port` | The HTTPS listener port (default `5001`). |

### Authentication

Operator endpoints are guarded by a single JWT bearer scheme: the `ra_operator` policy requires an
authenticated user with the `ra_operator` role. Unauthenticated requests to `/ra/*` are rejected with
`401` — the endpoints exist but are not reachable without a token. `/health` is open.

## Build and run

Each role publishes its own host binary; the per-engine Dockerfiles COPY that publish. The Cake
task `Appliance-Docker-Build` builds every role image, tagging each with `:latest` and the build
version:

```sh
# publish the RA host
dotnet publish src/hosts/opencertserver.host.ra -c Release -r linux-x64 \
    -p:InvariantGlobalization=true -o artifacts/publish/ra/linux-x64

# build the RA images (base + postgres + mssql), tagged :latest and :<version>
dotnet run --project build/opencertserver.build -c Release -- --target=Appliance-Docker-Build
```

The images run as the unprivileged UID `1654`. See [`docs/docker.md`](../../../docs/docker.md) and
[`docs/appliance.md`](../../../docs/appliance.md) for the full image catalog and the hardening
guarantees the IQ tests assert.

## Tests

The RA host is verified by the `RA appliance` scenario in
[`tests/opencertserver.iq.tests/Features/ApplianceContainers.feature`](../../../tests/opencertserver.iq.tests/Features/ApplianceContainers.feature),
which boots the image in a Linux container (via Testcontainers) and asserts the unprivileged user,
the TLS 1.3 handshake, the TLS 1.2 rejection, the omitted `Server` header, the healthy `/health`,
that the RA endpoints are exposed (and reject anonymous callers with 401), and that the EST, ACME,
CA, and SCEP endpoints are hidden.
