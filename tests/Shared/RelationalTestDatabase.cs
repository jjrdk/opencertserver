namespace OpenCertServer.Testing;

using System.Security.Cryptography;
using DotNet.Testcontainers.Builders;
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
                _container = new ContainerBuilder("postgres:17-alpine")
                    .WithEnvironment("POSTGRES_PASSWORD", password)
                    .WithEnvironment("POSTGRES_DB", "store_tests")
                    .WithPortBinding(5432, true)
                    .WithWaitStrategy(Wait.ForUnixContainer()
                        .UntilMessageIsLogged("PostgreSQL init process complete")
                        .UntilInternalTcpPortIsAvailable(5432))
                    .Build();
                await _container.StartAsync(cancellationToken);
                ConnectionString = new NpgsqlConnectionStringBuilder
                {
                    Host = _container.Hostname, Port = _container.GetMappedPublicPort(5432),
                    Database = "store_tests", Username = "postgres", Password = password,
                    Pooling = false
                }.ConnectionString;
                break;
            case "MSSQL":
                _container = new ContainerBuilder("mcr.microsoft.com/mssql/server:2022-latest")
                    .WithEnvironment("ACCEPT_EULA", "Y")
                    .WithEnvironment("MSSQL_PID", "Developer")
                    .WithEnvironment("MSSQL_SA_PASSWORD", password)
                    .WithPortBinding(1433, true)
                    .WithWaitStrategy(Wait.ForUnixContainer().UntilCommandIsCompleted(
                        ["/opt/mssql-tools18/bin/sqlcmd", "-S", "localhost", "-U", "sa",
                            "-P", password, "-C", "-Q", "SELECT 1"],
                        strategy => strategy.WithTimeout(TimeSpan.FromMinutes(3))))
                    .Build();
                await _container.StartAsync(cancellationToken);
                ConnectionString = new SqlConnectionStringBuilder
                {
                    DataSource = $"{_container.Hostname},{_container.GetMappedPublicPort(1433)}",
                    InitialCatalog = "store_tests", UserID = "sa", Password = password,
                    TrustServerCertificate = true, Pooling = false
                }.ConnectionString;
                break;
            default:
                throw new NotSupportedException($"No relational test database factory is registered for '{database}'.");
        }
        await MigrateAsync(cancellationToken);
    }

    public async Task MigrateAsync(CancellationToken cancellationToken)
    {
        var services = RegisterProvider(new ServiceCollection());
        using var provider = services.BuildServiceProvider();
        var options = new DbContextOptionsBuilder<CaDbContext>();
        provider.GetRequiredService<IRelationalStoreProvider>().Configure(options, ConnectionString);
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
