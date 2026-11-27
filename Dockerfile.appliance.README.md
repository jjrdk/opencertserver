# Unified appliance compatibility image

`Dockerfile.appliance` is the compatibility Dockerfile for the unified,
file-backed appliance. It exposes the same CA, EST, ACME, SCEP, and health
endpoints as `Dockerfile.unified`.

## Build

From the repository root run:

```sh
dotnet run --project build/opencertserver.build/opencertserver.build.csproj -c Release -f net11.0 -- --target=Appliance-Docker-Build
```

This builds `opencertserver-appliance-appliance:latest-net10.0` and
`:latest-net11.0`, plus versioned equivalents. `TFM`, `DOTNET_VERSION`,
`UBUNTU_CODENAME`, `RID`, and `PLATFORM` select the build: use
`net10.0`/`10.0`/`noble` or `net11.0`/`11.0`/`resolute`. The self-contained
unified host is published with invariant globalization to
`artifacts/publish/<TFM>/unified/<RID>/`. See the [manual build guide](docs/docker.md#build).

## Run and configure

Adapt [`deploy/appliance/unified.json`](deploy/appliance/unified.json), including
JWT, TLS/CA keys, OCSP/CRL URLs, and ACME settings. Mount the JSON and secrets
read-only and expose its configured port. Mount persistent
`/var/lib/opencertserver` writable by UID 1654; run only one writer. See the
[operator guide](docs/appliance.md) for a hardened run command and backup guidance.
