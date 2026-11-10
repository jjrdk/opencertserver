using Testcontainers.MsSql;
using Testcontainers.PostgreSql;

namespace OpenCertServer.Testing;

using System.Security.Cryptography;
using DotNet.Testcontainers.Containers;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Npgsql;
using OpenCertServer.Data;
using OpenCertServer.Data.MsSql;
using OpenCertServer.Data.PostgreSql;

internal sealed class RelationalTestDatabase(string database) : IAsyncDisposable
{
    private IContainer? _container;
    public string ConnectionString { get; private set; } = null!;

    public IServiceCollection RegisterProvider(IServiceCollection services) => database switch
    {
        "PostgreSQL" => services.AddPostgreSqlStore(),
        "MSSQL" => services.AddMsSqlStore(),
        _ => throw new NotSupportedException($"No relational test database factory is registered for '{database}'.")
    };

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var password = $"Ocs!{Convert.ToHexString(RandomNumberGenerator.GetBytes(24))}";
        switch (database)
        {
            case "PostgreSQL":
                var postgres = new PostgreSqlBuilder("postgres:alpine")
                    .WithUsername("postgres")
                    .WithPassword(password)
                    .WithDatabase("store_tests")
                    .Build();
                _container = postgres;
                await postgres.StartAsync(cancellationToken);
                ConnectionString = new NpgsqlConnectionStringBuilder(postgres.GetConnectionString())
                {
                    Pooling = false
                }.ConnectionString;
                break;
            case "MSSQL":
                // The module configures MSSQL_SA_PASSWORD and its sqlcmd readiness probe from WithPassword;
                // overriding the env var or wait strategy makes the probe log in with the wrong password.
                var msSql = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-latest")
                    .WithPassword(password)
                    .Build();
                _container = msSql;
                await msSql.StartAsync(cancellationToken);
                ConnectionString = new SqlConnectionStringBuilder(msSql.GetConnectionString())
                {
                    InitialCatalog = "store_tests", TrustServerCertificate = true, Pooling = false
                }.ConnectionString;
                break;
            default:
                throw new NotSupportedException($"No relational test database factory is registered for '{database}'.");
        }

        await MigrateAsync(cancellationToken);
    }

    public Task MigrateAsync(CancellationToken cancellationToken) => MigrateAsync(ConnectionString, cancellationToken);

    /// <summary>Creates and migrates a uniquely named database on the running server and returns its connection string.</summary>
    public async Task<string> CreateIsolatedDatabaseAsync(CancellationToken cancellationToken)
    {
        var name = $"t_{Guid.NewGuid():N}";
        var connectionString = database switch
        {
            "PostgreSQL" => new NpgsqlConnectionStringBuilder(ConnectionString) { Database = name }.ConnectionString,
            "MSSQL" => new SqlConnectionStringBuilder(ConnectionString) { InitialCatalog = name }.ConnectionString,
            _ => throw new NotSupportedException($"No relational test database factory is registered for '{database}'.")
        };
        await MigrateAsync(connectionString, cancellationToken);
        return connectionString;
    }

    private async Task MigrateAsync(string connectionString, CancellationToken cancellationToken)
    {
        if (database == "MSSQL")
        {
            var sqlConnectionString = new SqlConnectionStringBuilder(connectionString);
            var databaseName = sqlConnectionString.InitialCatalog;
            sqlConnectionString.InitialCatalog = "master";
            await using var connection = new SqlConnection(sqlConnectionString.ConnectionString);
            await connection.OpenAsync(cancellationToken);
            await using var command = connection.CreateCommand();
            command.CommandText = $"IF DB_ID(@databaseName) IS NULL CREATE DATABASE [{databaseName.Replace("]", "]]", StringComparison.Ordinal)}]";
            command.Parameters.Add("@databaseName", System.Data.SqlDbType.NVarChar, 128).Value = databaseName;
            await command.ExecuteNonQueryAsync(cancellationToken);
        }

        var services = RegisterProvider(new ServiceCollection());
        using var provider = services.BuildServiceProvider();
        var options = new DbContextOptionsBuilder<CaDbContext>();
        provider.GetRequiredService<IRelationalStoreProvider>().Configure(options, connectionString);
        await using var context = new CaDbContext(options.Options);
        await context.Database.MigrateAsync(cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (_container is not null)
        {
            await _container.DisposeAsync();
        }
    }
}
