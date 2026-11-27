# CA appliance with SQL Server

`Dockerfile.ca.mssql` runs the CA-only appliance with relational SQL Server
storage and serves `/ca/*` and `/health`.

## Build

From the repository root run:

```sh
dotnet run --project build/opencertserver.build/opencertserver.build.csproj -c Release -f net11.0 -- --target=Appliance-Docker-Build
```

The resulting `opencertserver-appliance-ca-mssql:latest-net10.0` and
`:latest-net11.0` images also have versioned tags. `TFM`, `DOTNET_VERSION`,
`UBUNTU_CODENAME`, `RID`, and `PLATFORM` select the build: use
`net10.0`/`10.0`/`noble` or `net11.0`/`11.0`/`resolute`. The self-contained
CA host is published **without** invariant globalization to
`artifacts/publish/<TFM>/ca/mssql/<RID>/`; the full base provides ICU.
See the [manual build guide](docs/docker.md#build).

## Run and configure

Adapt [`deploy/appliance/ca.json`](deploy/appliance/ca.json), mount it and
the TLS/CA secrets read-only, and expose its configured port. Supply the SQL
Server connection string through `ConnectionStrings__OpenCertServer` from a
secret source; the image selects the SQL Server relational provider. Apply
schema migrations before starting and validate database TLS. See
[relational storage](docs/appliance.md#relational-storage) and the
[operator guide](docs/appliance.md) for UID 1654, CA/RA bindings, and backups.
