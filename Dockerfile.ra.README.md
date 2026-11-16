# RA appliance

`Dockerfile.ra` builds the file-backed RA appliance. It exposes `/ra/*` and
`/health`, forwards issuance to a CA over mTLS, and holds no CA signing key.

## Build

From the repository root run:

```sh
dotnet run --project build/opencertserver.build/opencertserver.build.csproj -c Release -f net11.0 -- --target=Appliance-Docker-Build
```

This builds `opencertserver-appliance-ra:latest-net10.0` and
`:latest-net11.0`, plus versioned equivalents. `TFM`, `DOTNET_VERSION`,
`UBUNTU_CODENAME`, `RID`, and `PLATFORM` select the build: use
`net10.0`/`10.0`/`noble` or `net11.0`/`11.0`/`resolute`. The self-contained
RA host is published with invariant globalization to
`artifacts/publish/<TFM>/ra/<RID>/`. See the [manual build guide](docs/docker.md#build).

## Run and configure

Adapt [`deploy/appliance/ra.json`](deploy/appliance/ra.json), including the
JWT issuer, listener TLS certificate, `Ra:PeerUrl`, scope, profile, client
certificate, and CA trust roots. Mount the JSON and referenced secrets read-only
and expose its configured port; files must be readable by UID 1654. Configure
the corresponding RA identity and permitted scope/profile on the CA. See the
[operator guide](docs/appliance.md) for a hardened run command and CA/RA setup.
