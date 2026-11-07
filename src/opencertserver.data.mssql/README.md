# SQL Server relational stores

This optional adapter supplies Microsoft SQL Server (MSSQL) support for the engine-independent
`opencertserver.data` stores. It owns EF configuration, migrations, design-time tooling and
atomic nonce/revocation operations.

Register it after default ACME/CA services and before building the container:

```csharp
using OpenCertServer.Data;
using OpenCertServer.Data.MsSql;

services.AddMsSqlStore()
    .AddAcmeRelationalStore(configuration, "OpenCertServer")
    .AddCaRelationalStore(configuration, "OpenCertServer");
```

Supply `ConnectionStrings:OpenCertServer` through standard configuration, for example
`ConnectionStrings__OpenCertServer` from your deployment secret provider. Use SQL Server
connection-string syntax and protect transport with a trusted server certificate; do not
copy the tests' `TrustServerCertificate` setting into production. Both stores must use the
same connection. The standalone certserver remains wired to PostgreSQL; embedding hosts
choose this adapter explicitly.

## Schema deployment

Run migrations once from an untrimmed JIT deployment tool, not automatically on server startup:

```sh
dotnet ef database update --project src/opencertserver.data.mssql
dotnet ef migrations script --idempotent --project src/opencertserver.data.mssql
```

The tooling reads `ConnectionStrings__OpenCertServer` by default. To use another standard
connection-string name, append `-- MyDatabase`. Missing or blank connections fail explicitly.
Embedded deployment tools can call `CaStoreMigration.MigrateAsync(connection, cancellationToken)`.
Use an EF CLI matching the centrally pinned EF Core version. Give schema permissions only
to the migration identity, and back up the database before upgrades.

String columns use `Latin1_General_100_BIN2` collation to preserve case-sensitive ACME
identifiers/nonces regardless of the database default. Certificate validity dates use
`DateTimeOffset` mapped to SQL Server `datetimeoffset` and are stored with a UTC offset.
The initial migration, its target model and the model snapshot use the same mapping.
Accounts, orders and EAB keys retain the shared optimistic-concurrency policy;
nonce insertion is idempotent and consumption is atomic.

Provider-specific operations and migrations publish OpenTelemetry through the
`opencertserver.data.mssql` meter and activity source. Only fixed operation names
are recorded; SQL, connection strings, nonce values, certificate identifiers, profile
names, and exception messages are excluded.

## Qualification

Both relational BDD features have PostgreSQL and MSSQL example rows. They use real
`postgres:17-alpine` and `mcr.microsoft.com/mssql/server:2022-latest` containers, respectively:

```sh
dotnet test --project tests/opencertserver.data.tests
dotnet test --project tests/opencertserver.certserver.tests --filter-class '*Relational*'
```

SQL Server requires an x86-64 Docker runtime or working AMD64 emulation, sufficient container
memory, and acceptance of its container EULA (the test fixture sets `ACCEPT_EULA=Y`).
Native AOT/trimmed deployments are not qualified; use untrimmed JIT.
CA private keys, tenant isolation, distributed worker leases, retention jobs and cluster-wide
CRL-number allocation are outside this adapter. See [operational limits](../../docs/getting-started.md#postgresql-persistence).
