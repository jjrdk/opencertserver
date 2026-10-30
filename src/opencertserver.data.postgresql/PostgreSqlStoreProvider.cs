namespace OpenCertServer.Data.PostgreSql;

using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Npgsql;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>PostgreSQL configuration and atomic SQL operations for the shared relational stores.</summary>
public sealed class PostgreSqlStoreProvider : IRelationalStoreProvider
{
    /// <inheritdoc />
    public void Configure(DbContextOptionsBuilder options, string connectionString) =>
        options.UseNpgsql(connectionString,
            provider => provider.MigrationsAssembly(typeof(PostgreSqlStoreProvider).Assembly.GetName().Name));

    /// <inheritdoc />
    public bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation };

    /// <inheritdoc />
    public async Task SaveNonceAsync(CaDbContext context, Nonce nonce, CancellationToken cancellationToken) =>
        await context.Database.ExecuteSqlInterpolatedAsync(
            $"""INSERT INTO "Nonces" ("Token", "Created") VALUES ({nonce.Token}, {DateTimeOffset.UtcNow}) ON CONFLICT ("Token") DO NOTHING""",
            cancellationToken);

    /// <inheritdoc />
    public async Task<bool> TryRemoveNonceAsync(CaDbContext context, Nonce nonce, CancellationToken cancellationToken) =>
        await context.Database.ExecuteSqlInterpolatedAsync(
            $"""DELETE FROM "Nonces" WHERE "Token" = {nonce.Token}""", cancellationToken) == 1;

    /// <inheritdoc />
    public async Task<bool> RevokeCertificateAsync(CaDbContext context, string serialNumber,
        X509RevocationReason reason, CancellationToken cancellationToken) =>
        await context.Database.ExecuteSqlInterpolatedAsync(
            $"""UPDATE "Certificates" SET "RevocationReason" = {(int)reason}, "RevocationDate" = {DateTimeOffset.UtcNow} WHERE "SerialNumber" = {serialNumber}""",
            cancellationToken) == 1;

    /// <inheritdoc />
    public async IAsyncEnumerable<CertificateItemInfo> ReadCertificatePage(CaDbContext context,
        int page, int pageSize, bool revokedOnly, [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await context.Database.OpenConnectionAsync(cancellationToken);
        try
        {
            await using var command = context.Database.GetDbConnection().CreateCommand();
            // EF's experimental precompiler aliases Skip/Take parameters; keep distinct SQL parameters.
            const string columns = """
                SELECT "SerialNumber", "DistinguishedName", "Issuer", "NotBefore", "NotAfter",
                       "Thumbprint", "RevocationReason", "RevocationDate" FROM "Certificates"
                """;
            command.CommandText = columns + (revokedOnly ? """ WHERE "RevocationReason" IS NOT NULL""" : "")
                + """ ORDER BY "SerialNumber" LIMIT @size OFFSET @offset""";
            var size = command.CreateParameter();
            size.ParameterName = "size";
            size.Value = pageSize;
            command.Parameters.Add(size);
            var offset = command.CreateParameter();
            offset.ParameterName = "offset";
            offset.Value = checked(page * pageSize);
            command.Parameters.Add(offset);
            await using var reader = await command.ExecuteReaderAsync(cancellationToken);
            while (await reader.ReadAsync(cancellationToken))
            {
                yield return new CertificateItemInfo
                {
                    SerialNumber = reader.GetString(0),
                    DistinguishedName = reader.GetString(1),
                    Issuer = reader.IsDBNull(2) ? null : reader.GetString(2),
                    NotBefore = reader.GetDateTime(3),
                    NotAfter = reader.GetDateTime(4),
                    Thumbprint = reader.GetString(5),
                    RevocationReason = reader.IsDBNull(6) ? null : (X509RevocationReason)reader.GetInt32(6),
                    RevocationDate = reader.IsDBNull(7) ? null : reader.GetFieldValue<DateTimeOffset>(7)
                };
            }
        }
        finally
        {
            await context.Database.CloseConnectionAsync();
        }
    }
}

/// <summary>Opt-in registration of the PostgreSQL dependency; the shared data project references no engine.</summary>
public static class PostgreSqlStoreExtensions
{
    /// <summary>Selects PostgreSQL for subsequent relational-store registrations.</summary>
    public static IServiceCollection AddPostgreSqlStore(this IServiceCollection services)
    {
        services.TryAddSingleton<IRelationalStoreProvider, PostgreSqlStoreProvider>();
        return services;
    }
}
