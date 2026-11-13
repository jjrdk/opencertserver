using DotNet.Testcontainers.Networks;
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

    /// <summary>The network alias the database is reachable by from containers on its network.</summary>
    public string Alias { get; } = "db";

    /// <summary>The connection string a sibling container on the database's network uses (host = <see cref="Alias"/>).</summary>
    public string NetworkConnectionString { get; private set; } = null!;

    /// <summary>The running database container, for attaching a sibling container to its network.</summary>
    public IContainer Container => _container!;

    /// <summary>The network the database lives on, or null when it runs on Testcontainers' default network.</summary>
    public INetwork? Network { get; private set; }

    /// <summary>The fixed database name the appliance and the queries target.</summary>
    public string DatabaseName { get; } = "store_tests";

    public IServiceCollection RegisterProvider(IServiceCollection services) => database switch
    {
        "PostgreSQL" => services.AddPostgreSqlStore(),
        "MSSQL" => services.AddMsSqlStore(),
        _ => throw new NotSupportedException($"No relational test database factory is registered for '{database}'.")
    };

    public async Task StartAsync(CancellationToken cancellationToken)
        => await StartAsync(null, cancellationToken).ConfigureAwait(false);

    /// <summary>Starts the database and migrates it, optionally attaching it to an existing network under <see cref="Alias"/>.</summary>
    public async Task StartAsync(INetwork? network, CancellationToken cancellationToken)
    {
        var password = $"Ocs!{Convert.ToHexString(RandomNumberGenerator.GetBytes(24))}";
        switch (database)
        {
            case "PostgreSQL":
            {
                var builder = new PostgreSqlBuilder("postgres:alpine")
                    .WithUsername("postgres")
                    .WithPassword(password)
                    .WithDatabase(DatabaseName);
                if (network is not null)
                {
                    builder = builder.WithNetwork(network).WithNetworkAliases(Alias);
                }
                _container = builder.Build();
                await _container.StartAsync(cancellationToken);
                ConnectionString = new NpgsqlConnectionStringBuilder(_container.GetConnectionString())
                {
                    Pooling = false
                }.ConnectionString;
                NetworkConnectionString = new NpgsqlConnectionStringBuilder
                {
                    Host = Alias,
                    Port = 5432,
                    Username = "postgres",
                    Password = password,
                    Database = DatabaseName,
                    Pooling = false
                }.ConnectionString;
                Network = network;
                break;
            }
            case "MSSQL":
            {
                // The module configures MSSQL_SA_PASSWORD and its sqlcmd readiness probe from WithPassword;
                // overriding the env var or wait strategy makes the probe log in with the wrong password.
                var builder = new MsSqlBuilder("mcr.microsoft.com/mssql/server:2022-latest")
                    .WithPassword(password);
                if (network is not null)
                {
                    builder = builder.WithNetwork(network).WithNetworkAliases(Alias);
                }
                _container = builder.Build();
                await _container.StartAsync(cancellationToken);
                ConnectionString = new SqlConnectionStringBuilder(_container.GetConnectionString())
                {
                    InitialCatalog = DatabaseName, TrustServerCertificate = true, Pooling = false
                }.ConnectionString;
                // MSSQL encodes the port in the DataSource (SqlConnectionStringBuilder has no Port property).
                NetworkConnectionString = new SqlConnectionStringBuilder
                {
                    DataSource = $"{Alias},1433",
                    UserID = "sa",
                    Password = password,
                    InitialCatalog = DatabaseName,
                    TrustServerCertificate = true,
                    Pooling = false
                }.ConnectionString;
                Network = network;
                break;
            }
            default:
                throw new NotSupportedException($"No relational test database factory is registered for '{database}'.");
        }

        if (database == "PostgreSQL")
        {
            await WaitForHostConnectionAsync(cancellationToken);
        }
        await MigrateAsync(cancellationToken);
    }

    private async Task WaitForHostConnectionAsync(CancellationToken cancellationToken)
    {
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromMinutes(1));
        while (true)
        {
            // Container-local readiness does not establish that Docker's mapped host port is usable.
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(ConnectionString)
            {
                Timeout = 2
            }.ConnectionString);
            try
            {
                await connection.OpenAsync(deadline.Token);
                return;
            }
            catch (NpgsqlException exception) when (exception.IsTransient)
            {
                await Console.Error.WriteLineAsync($"Waiting for {database} host connection: {exception.Message}");
                await Task.Delay(TimeSpan.FromSeconds(1), deadline.Token);
            }
        }
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

    /// <summary>Runs the schema migration against a connection string (used for isolated and network databases).</summary>
    public async Task MigrateAsync(string connectionString, CancellationToken cancellationToken)
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

    /// <summary>Queries the relational database from the host, asserting a row the appliance seeded. Returns the row count.</summary>
    public Task<int> QueryRowCountAsync(string sql, CancellationToken cancellationToken)
        => database switch
        {
            "MSSQL" => QueryMssSqlRowCountAsync(sql, cancellationToken),
            "PostgreSQL" => QueryPostgresRowCountAsync(sql, cancellationToken),
            _ => throw new NotSupportedException($"No relational test database factory is registered for '{database}'.")
        };

    private async Task<int> QueryMssSqlRowCountAsync(string sql, CancellationToken cancellationToken)
    {
        await using var connection = new SqlConnection(ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken),
            System.Globalization.CultureInfo.InvariantCulture);
    }

    private async Task<int> QueryPostgresRowCountAsync(string sql, CancellationToken cancellationToken)
    {
        await using var connection = new NpgsqlConnection(ConnectionString);
        await connection.OpenAsync(cancellationToken);
        await using var command = connection.CreateCommand();
        command.CommandText = sql;
        return Convert.ToInt32(await command.ExecuteScalarAsync(cancellationToken),
            System.Globalization.CultureInfo.InvariantCulture);
    }

    public async ValueTask DisposeAsync()
    {
        if (_container is not null)
        {
            await _container.DisposeAsync();
        }
    }
}
