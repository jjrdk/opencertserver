# CA appliance

`Dockerfile.ca` builds the CA-only, file-backed appliance. It serves `/ca/*` and
`/health`; it does not expose EST, ACME, SCEP, or RA endpoints.

## Build

From the repository root, run:

```sh
dotnet run --project build/opencertserver.build/opencertserver.build.csproj -c Release -f net11.0 -- --target=Appliance-Docker-Build
```

This builds `opencertserver-appliance-ca:latest-net10.0` and
`:latest-net11.0`, plus versioned equivalents. The Dockerfile accepts `TFM`,
`DOTNET_VERSION`, `UBUNTU_CODENAME`, `RID`, and `PLATFORM`. The task uses
`net10.0`/`10.0`/`noble` or `net11.0`/`11.0`/`resolute`, and publishes the
CA host self-contained with invariant globalization to
`artifacts/publish/<TFM>/ca/<RID>/`. See the [manual build example](docs/docker.md#build).

## Run and configure

Adapt [`deploy/appliance/ca.json`](deploy/appliance/ca.json) for the JWT issuer,
TLS and CA key paths, allowed hosts, and externally reachable OCSP/CRL URLs.
Mount it read-only at `/config/appsettings.json` (or set `OPENCERT_CONFIG`);
mount the referenced secrets read-only at `/run/secrets`. The configured `port`
controls the listener. Mount a writable, persistent `/var/lib/opencertserver`
owned by UID 1654; run only one writer. See the [operator guide](docs/appliance.md)
for a hardened run command, CA/RA binding, backup, and upgrade guidance.
