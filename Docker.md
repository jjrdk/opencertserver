# Container deployments

The appliance images are source-built .NET 10 Alpine containers. For role selection,
configuration, TLS, trust, storage, backup, upgrades, and rollback, follow the
[headless appliance operator guide](docs/appliance.md).

| Dockerfile | Role |
|---|---|
| `Dockerfile.unified` or `Dockerfile.appliance` | Unified CA + EST + ACME server |
| `Dockerfile.ca` | Existing CA HTTP endpoints (`/ca/*`) and health only |
| `Dockerfile.ra` | Operator-facing RA API backed by the outbound `RaPeerClient` |

Build images from the repository root:

```sh
docker build -f Dockerfile.unified -t opencertserver-unified:local .
docker build -f Dockerfile.ca -t opencertserver-ca:local .
docker build -f Dockerfile.ra -t opencertserver-ra:local .
```

The samples in [`deploy/appliance/`](deploy/appliance/) are starting configurations, not
production secrets. Replace example hostnames and file paths, provision your own keys and
certificates, and apply the permissions and persistence guidance in the operator guide.
Do not use mutable `latest` tags or share a writable CA state volume between replicas.

The appliance images run as UID 1654, use TLS 1.3, and expect a mounted configuration file
at `/config/appsettings.json` by default. Configuration is mounted read-only; environment
variables and then command-line arguments can override it. The CA and unified roles need
persistent writable state at `/var/lib/opencertserver`; the RA role has no local issuing keys
or CA state.
