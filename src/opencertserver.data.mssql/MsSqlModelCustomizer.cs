namespace OpenCertServer.Data.MsSql;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;

/// <summary>Applies SQL Server conventions without coupling the shared context to an engine.</summary>
public sealed class MsSqlModelCustomizer(ModelCustomizerDependencies dependencies) : RelationalModelCustomizer(dependencies)
{
    /// <inheritdoc />
    public override void Customize(ModelBuilder modelBuilder, DbContext context)
    {
        base.Customize(modelBuilder, context);
        // Column collation also works when migrations target an existing case-insensitive database.
        foreach (var property in modelBuilder.Model.GetEntityTypes().SelectMany(e => e.GetProperties())
                     .Where(p => p.ClrType == typeof(string)))
        {
            property.SetCollation("Latin1_General_100_BIN2");
        }
//        // SQL Server datetime2 does not retain DateTime.Kind.
//        modelBuilder.Entity<CertificateEntity>().Property(c => c.NotBefore)
//            .HasConversion<UtcDateTimeConverter>();
//        modelBuilder.Entity<CertificateEntity>().Property(c => c.NotAfter)
//            .HasConversion<UtcDateTimeConverter>();
    }
}
