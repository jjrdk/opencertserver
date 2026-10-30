# PostgreSQL relational-store adapter

Optional PostgreSQL dependency for the provider-independent `opencertserver.data` stores.
It owns Npgsql configuration, unique-violation classification, atomic nonce/revocation SQL,
certificate paging, migrations and the design-time context factory.

Register `services.AddPostgreSqlStore()` before the explicit shared
`AddAcmeRelationalStore(configuration, connectionStringName)` and/or
`AddCaRelationalStore(configuration, connectionStringName)` methods.
They read the standard `ConnectionStrings:<name>` entry. The standalone certserver uses
the name `OpenCertServer`.
This adapter is qualified for untrimmed JIT deployments; Native AOT requires additional
provider-specific model/query generation and runtime integration.

Apply migrations separately from server startup, using a matching EF CLI and a connection
supplied by a deployment secret provider through `ConnectionStrings__OpenCertServer`:

```sh
dotnet ef database update --project src/opencertserver.data.postgresql
dotnet ef migrations script --idempotent --project src/opencertserver.data.postgresql
```

Pass another connection name after `--` (for example `-- MyDatabase`) to read
`ConnectionStrings__MyDatabase`. Missing or blank connections are rejected; there is no
legacy-key or localhost fallback.

`OpenCertServer.Data.CaStoreMigration.MigrateAsync(connection, cancellationToken)` is
also available from this adapter for JIT deployment tools. The existing migration ID and
schema are preserved; an already migrated database does not need to be recreated.
Do not grant routine server credentials schema-modification permissions.

See [the setup guide](../../docs/getting-started.md#postgresql-persistence) and
[shared adapter contract](../opencertserver.data/README.md).
