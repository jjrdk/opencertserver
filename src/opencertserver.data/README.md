# OpenCertServer Data

Provider-independent EF Core models, `CaDbContext`, aggregate serialization and stores for
ACME accounts, orders, nonces, external-account keys and CA certificate inventory.
This project references no database engine and contains no engine-specific SQL or migrations.

## Select a provider

Reference the desired adapter dependency in your host. PostgreSQL and Microsoft SQL Server
(MSSQL) adapters are available. For PostgreSQL:

```csharp
using OpenCertServer.Data;
using OpenCertServer.Data.PostgreSql;

services.AddPostgreSqlStore()
    .AddAcmeRelationalStore(configuration, "OpenCertServer")
    .AddCaRelationalStore(configuration, "OpenCertServer");
```

Register after the default ACME/CA services and before building the service provider.
For SQL Server, reference `opencertserver.data.mssql`, import `OpenCertServer.Data.MsSql`
and use `AddMsSqlStore()` instead of `AddPostgreSqlStore()`.
The configuration overloads require a name and read only `ConnectionStrings:<name>` via
`GetConnectionString`. Choose any connection name in an embedding host; the standalone host
uses `OpenCertServer` (environment variable `ConnectionStrings__OpenCertServer`).
These methods register only relational storage, never memory/file modes.
Alternatively, call `AddAcmeRelationalStore(connection)` and/or `AddCaRelationalStore(connection)`
after registering the adapter. Missing providers/connections fail explicitly.
ACME and CA must use the same connection when both use relational storage.
Memory/file registrations remain separate and need no adapter.

## Add another engine

Create a separate adapter project that references this project and the engine's EF provider.
Implement and register `IRelationalStoreProvider` before selecting relational storage:

- Configure the EF provider, migrations assembly and any provider-specific model conventions.
- Classify unique-constraint violations so the shared aggregate stores translate concurrency conflicts.
- Implement idempotent nonce insertion, atomic nonce consumption and certificate revocation.
- Read deterministic, database-paged certificate inventory/revocations, preserving cancellation
  and UTC timestamps. The caller owns the supplied context's lifetime.
- Own the engine's migrations and design-time context factory in the adapter.

Reuse the database-table BDD scenarios and add the provider to their test factory when ready.
The PostgreSQL and MSSQL adapters exercise the same contracts; Redis is not included.

Use untrimmed JIT deployments. Native AOT requires provider-specific compiled-model/query
integration; the previous native qualification does not apply after the provider split.
See [PostgreSQL setup](../../docs/getting-started.md#postgresql-persistence) for configuration,
migration commands and operational limits.
