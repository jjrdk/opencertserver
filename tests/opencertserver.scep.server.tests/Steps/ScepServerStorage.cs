namespace OpenCertServer.Scep.Tests.Steps;

using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Data;
using OpenCertServer.Testing;
using Reqnroll;

/// <summary>
/// Selects the persistence used by the SCEP certificate server steps, as chosen by
/// <c>Given the certificate server storage is "&lt;Storage&gt;"</c> (<c>in-memory</c>, <c>postgresql</c> or <c>mssql</c>).
/// Relational providers share one container per test run; every scenario gets an isolated database.
/// </summary>
[Binding]
public sealed class ScepServerStorage
{
    private const string StorageKey = "ScepServerStorage";
    private const string InMemory = "in-memory";
    private static readonly ConcurrentDictionary<string, Lazy<Task<RelationalTestDatabase>>> Databases = new();

    private readonly RelationalTestDatabase? _database;
    private readonly string? _connectionString;

    private readonly ScenarioContext? _scenarioContext;

    public ScepServerStorage(ScenarioContext scenarioContext) => _scenarioContext = scenarioContext;

    private ScepServerStorage(RelationalTestDatabase? database, string? connectionString)
    {
        _database = database;
        _connectionString = connectionString;
    }

    internal static async Task<ScepServerStorage> Create(
        ScenarioContext scenarioContext,
        CancellationToken cancellationToken)
    {
        var storage = scenarioContext.TryGetValue(StorageKey, out string? selected) && selected is not null
            ? selected
            : InMemory;
        var provider = storage.ToLowerInvariant() switch
        {
            InMemory => null,
            "postgresql" => "PostgreSQL",
            "mssql" => "MSSQL",
            _ => throw new ArgumentException(
                $"Unsupported certificate server storage '{storage}'. Use in-memory, postgresql or mssql.")
        };
        if (provider is null)
        {
            return new ScepServerStorage(null, null);
        }

        var database = await Databases.GetOrAdd(
            provider,
            p => new Lazy<Task<RelationalTestDatabase>>(() => Start(p))).Value;
        var connectionString = await database.CreateIsolatedDatabaseAsync(cancellationToken);
        return new ScepServerStorage(database, connectionString);
    }

    internal static void Select(ScenarioContext scenarioContext, string storage) =>
        scenarioContext[StorageKey] = storage;

    [Given("the certificate server storage is {string}")]
    public void GivenTheCertificateServerStorageIs(string storage) => Select(_scenarioContext!, storage);

    internal void Register(IServiceCollection services)
    {
        if (_database is null)
        {
            return;
        }

        _database.RegisterProvider(services);
        services.AddCaRelationalStore(_connectionString!);
    }

    [AfterTestRun]
    public static async Task DisposeDatabases()
    {
        foreach (var database in Databases.Values.Where(d => d.IsValueCreated))
        {
            try
            {
                await (await database.Value).DisposeAsync();
            }
            catch (Exception)
            {
                // A container that failed to start has nothing to dispose.
            }
        }

        Databases.Clear();
    }

    private static async Task<RelationalTestDatabase> Start(string provider)
    {
        var database = new RelationalTestDatabase(provider);
        await database.StartAsync(CancellationToken.None);
        return database;
    }
}
