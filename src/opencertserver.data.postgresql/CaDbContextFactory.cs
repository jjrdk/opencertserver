using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;
using Microsoft.Extensions.Configuration;

namespace OpenCertServer.Data.PostgreSql;

/// <summary>
/// EF Core design-time factory so <c>dotnet ef migrations</c> can construct the context outside the app host.
/// Reads the standard ConnectionStrings environment configuration. The first tooling argument
/// selects the connection name; the default is OpenCertServer.
/// </summary>
public class CaDbContextFactory : IDesignTimeDbContextFactory<CaDbContext>
{
    /// <inheritdoc />
    public CaDbContext CreateDbContext(string[] args)
    {
        var name = args.Length == 0 ? "OpenCertServer" : args[0];
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        var configuration = new ConfigurationBuilder().AddEnvironmentVariables().Build();
        var connectionString = configuration.GetConnectionString(name);
        if (string.IsNullOrWhiteSpace(connectionString))
        {
            throw new InvalidOperationException($"Configure ConnectionStrings:{name}.");
        }

        var options = new DbContextOptionsBuilder<CaDbContext>();
        new PostgreSqlStoreProvider().Configure(options, connectionString);

        return new CaDbContext(options.Options);
    }
}