using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore;

namespace OpenCertServer.Data.PostgreSql;

/// <summary>PostgreSQL schema management for a separate, non-AOT deployment step.</summary>
public static class CaStoreMigration
{
    /// <summary>Applies pending migrations. Do not invoke from a Native AOT application.</summary>
    [RequiresDynamicCode("Run EF migrations in a separate JIT deployment process.")]
    [RequiresUnreferencedCode("EF migrations require untrimmed migration metadata.")]
    public static async Task MigrateAsync(string connectionString, CancellationToken cancellationToken = default)
    {
        var options = new DbContextOptionsBuilder<CaDbContext>();
        new PostgreSqlStoreProvider().Configure(options, connectionString);
        await using var db = new CaDbContext(options.Options);
        await db.Database.MigrateAsync(cancellationToken);
    }
}
