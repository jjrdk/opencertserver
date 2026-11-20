# Unified appliance with SQL Server

`Dockerfile.unified.mssql` runs the unified CA, EST, ACME, SCEP, and health
endpoints using relational SQL Server storage.

## Build

From the repository root run:

```sh
dotnet run --project build/opencertserver.build/opencertserver.build.csproj -c Release -f net11.0 -- --target=Appliance-Docker-Build
```

This builds `opencertserver-appliance-unified-mssql:latest-net10.0` and
`:latest-net11.0`, plus versioned equivalents. `TFM`, `DOTNET_VERSION`,
`UBUNTU_CODENAME`, `RID`, and `PLATFORM` select the build: use
`net10.0`/`10.0`/`noble` or `net11.0`/`11.0`/`resolute`. Publish the unified
host self-contained **without** invariant globalization to
`artifacts/publish/<TFM>/unified/mssql/<RID>/`; the full base provides ICU.
See the [manual build guide](docs/docker.md#build).

## Run and configure

Adapt [`deploy/appliance/unified.json`](deploy/appliance/unified.json), including
JWT, TLS/CA keys, OCSP/CRL URLs, and ACME settings. Mount the JSON and secrets
read-only and expose its configured port; files must be readable by UID 1654.
Supply `ConnectionStrings__OpenCertServer` from a secret source and apply the
SQL Server schema migration before starting. See [relational storage](docs/appliance.md#relational-storage)
and the [operator guide](docs/appliance.md).
