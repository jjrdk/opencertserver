namespace OpenCertServer.Data;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenCertServer.Acme.Abstractions.Storage;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Data.Stores;

/// <summary>Opt-in, provider-independent persistence for the ACME server and CA inventory.</summary>
public static class CaStoreExtensions
{
    /// <summary>Registers ACME stores using the separately registered <see cref="IRelationalStoreProvider"/>.</summary>
    public static IServiceCollection AddAcmeRelationalStore(this IServiceCollection services, string connectionString)
    {
        RegisterContext(services, connectionString);
        services.RemoveAll<IStoreAccounts>();
        services.RemoveAll<IStoreOrders>();
        services.RemoveAll<INonceStore>();
        services.RemoveAll<IStoreExternalAccountKeys>();
        services.AddSingleton<IStoreAccounts, RelationalAccountStore>();
        services.AddSingleton<IStoreOrders, RelationalOrderStore>();
        services.AddSingleton<INonceStore, RelationalNonceStore>();
        services.AddSingleton<IStoreExternalAccountKeys, RelationalExternalAccountKeyStore>();
        return services;
    }

    /// <summary>Registers certificate storage using the separately registered <see cref="IRelationalStoreProvider"/>.</summary>
    public static IServiceCollection AddCaRelationalStore(this IServiceCollection services, string connectionString)
    {
        RegisterContext(services, connectionString);
        services.RemoveAll<IStoreCertificates>();
        services.AddSingleton<IStoreCertificates, RelationalCertificateStore>();
        return services;
    }

    /// <summary>Registers ACME relational stores using a named entry in ConnectionStrings.</summary>
    public static IServiceCollection AddAcmeRelationalStore(this IServiceCollection services,
        IConfiguration configuration, string connectionStringName) =>
        services.AddAcmeRelationalStore(Connection(configuration, connectionStringName));

    /// <summary>Registers CA relational storage using a named entry in ConnectionStrings.</summary>
    public static IServiceCollection AddCaRelationalStore(this IServiceCollection services,
        IConfiguration configuration, string connectionStringName) =>
        services.AddCaRelationalStore(Connection(configuration, connectionStringName));

    private static string Connection(IConfiguration configuration, string connectionStringName)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionStringName);
        var connection = configuration.GetConnectionString(connectionStringName);
        return !string.IsNullOrWhiteSpace(connection) ? connection
            : throw new InvalidOperationException($"Configure ConnectionStrings:{connectionStringName}.");
    }

    private static void RegisterContext(IServiceCollection services, string connectionString)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectionString);
        if (services.All(d => d.ServiceType != typeof(IRelationalStoreProvider)))
        {
            throw new InvalidOperationException("Register an IRelationalStoreProvider before selecting relational storage.");
        }
        if (services.FirstOrDefault(d => d.ServiceType == typeof(RelationalStoreOptions))?.ImplementationInstance is RelationalStoreOptions registered)
        {
            if (!string.Equals(registered.Connection, connectionString, StringComparison.Ordinal))
            {
                throw new InvalidOperationException("ACME and CA relational stores must use the same database connection.");
            }

            return;
        }
        services.AddSingleton(new RelationalStoreOptions { Connection = connectionString });
        services.AddDbContext<CaDbContext>((provider, options) =>
            provider.GetRequiredService<IRelationalStoreProvider>().Configure(options, connectionString));
    }
}
