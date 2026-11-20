# RA appliance with PostgreSQL

`Dockerfile.ra.postgres` runs the RA appliance with the PostgreSQL provider
selected. It exposes `/ra/*` and `/health` and forwards issuance to the CA over mTLS.

## Build

From the repository root run:

```sh
dotnet run --project build/opencertserver.build/opencertserver.build.csproj -c Release -f net11.0 -- --target=Appliance-Docker-Build
```

This builds `opencertserver-appliance-ra-postgres:latest-net10.0` and
`:latest-net11.0`, plus versioned equivalents. `TFM`, `DOTNET_VERSION`,
`UBUNTU_CODENAME`, `RID`, and `PLATFORM` select the build: use
`net10.0`/`10.0`/`noble` or `net11.0`/`11.0`/`resolute`. Publish the RA host
self-contained with invariant globalization to
`artifacts/publish/<TFM>/ra/<RID>/`. See the [manual build guide](docs/docker.md#build).

## Run and configure

Adapt [`deploy/appliance/ra.json`](deploy/appliance/ra.json), including the
CA peer, mTLS identity, trust roots, JWT issuer, scope and profile. Mount the
JSON and secrets read-only and expose its configured port; files must be readable
by UID 1654. Configure the matching RA identity on the CA. The RA does not issue
or persist CA data, so its relational selection is inert; configure the database
on the CA or unified role instead. See [relational storage](docs/appliance.md#relational-storage)
and the [operator guide](docs/appliance.md).
