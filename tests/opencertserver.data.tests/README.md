# Relational store contracts

`Features/RelationalStores.feature` runs each database-backed outline against PostgreSQL
and MSSQL using its `Examples` table. The linked `tests/Shared/RelationalTestDatabase.cs`
fixture selects the adapter, starts an isolated container and applies its migrations.
The certserver relational feature uses the same fixture and provider table.

```sh
dotnet test --project tests/opencertserver.data.tests
dotnet test --project tests/opencertserver.certserver.tests --filter-class '*Relational*'
```

Docker must be available. MSSQL uses SQL Server 2022 Developer with `ACCEPT_EULA=Y`;
it requires x86-64 execution or working AMD64 emulation and sufficient memory.
Credentials are generated per container, not checked into configuration.
Unknown database names fail explicitly rather than selecting a default or skipping scenarios.

For PostgreSQL, after container-local readiness, the fixture also waits for an
authenticated connection through Docker's mapped host port before applying migrations.
Only transient connection failures are retried, within a one-minute startup deadline;
migration errors still fail
immediately. This avoids starting migrations before host-side connectivity is ready when
multiple test assemblies start containers together.