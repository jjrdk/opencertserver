namespace OpenCertServer.Data.MsSql;

using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore;

/// <summary>SQL Server schema management for a separate, untrimmed JIT deployment step.</summary>
public static class CaStoreMigration
{
    /// <summary>Applies pending migrations outside the application startup path.</summary>
    [RequiresDynamicCode("Run EF migrations in a separate JIT deployment process.")]
    [RequiresUnreferencedCode("EF migrations require untrimmed migration metadata.")]
    public static async Task MigrateAsync(string connectionString, CancellationToken cancellationToken = default)
    {
        var options = new DbContextOptionsBuilder<CaDbContext>();
        new MsSqlStoreProvider().Configure(options, connectionString);
        await using var context = new CaDbContext(options.Options);
        await context.Database.MigrateAsync(cancellationToken);
    }
}
