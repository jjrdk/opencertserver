namespace OpenCertServer.Data.MsSql;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

/// <summary>Creates SQL Server contexts from standard named ConnectionStrings environment configuration.</summary>
public sealed class CaDbContextFactory : IDesignTimeDbContextFactory<CaDbContext>
{
    /// <inheritdoc />
    public CaDbContext CreateDbContext(string[] args)
    {
        var name = args.Length == 0 ? "OpenCertServer" : args[0];
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var configuration = new ConfigurationBuilder().AddEnvironmentVariables().Build();
        var connection = configuration.GetConnectionString(name);
        if (string.IsNullOrWhiteSpace(connection))
        {
            throw new InvalidOperationException($"Configure ConnectionStrings:{name}.");
        }
        var options = new DbContextOptionsBuilder<CaDbContext>();
        new MsSqlStoreProvider().Configure(options, connection);
        return new CaDbContext(options.Options);
    }
}
