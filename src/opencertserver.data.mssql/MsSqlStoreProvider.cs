namespace OpenCertServer.Data.MsSql;

using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>SQL Server configuration and atomic operations for the shared relational stores.</summary>
public sealed class MsSqlStoreProvider : IRelationalStoreProvider
{
    /// <inheritdoc />
    public void Configure(DbContextOptionsBuilder options, string connectionString) =>
        options.UseSqlServer(connectionString,
                provider => provider.MigrationsAssembly(typeof(MsSqlStoreProvider).Assembly.GetName().Name))
            .ReplaceService<IModelCustomizer, MsSqlModelCustomizer>();

    /// <inheritdoc />
    public bool IsUniqueViolation(DbUpdateException exception) =>
        exception.InnerException is SqlException { Number: 2601 or 2627 };

    /// <inheritdoc />
    public async Task SaveNonceAsync(CaDbContext context, Nonce nonce, CancellationToken cancellationToken)
    {
        using var telemetry = MsSqlInstruments.Start("save_nonce");
        await context.Database.ExecuteSqlInterpolatedAsync(
            $"""
             INSERT INTO [Nonces] ([Token], [Created])
             SELECT {nonce.Token}, {DateTimeOffset.UtcNow}
             WHERE NOT EXISTS (
                 SELECT 1 FROM [Nonces] WITH (UPDLOCK, HOLDLOCK) WHERE [Token] = {nonce.Token})
             """, cancellationToken);
        telemetry.Complete();
    }

    /// <inheritdoc />
    public async Task<bool> TryRemoveNonceAsync(
        CaDbContext context,
        Nonce nonce,
        CancellationToken cancellationToken)
    {
        using var telemetry = MsSqlInstruments.Start("consume_nonce");
        var removed = await context.Database.ExecuteSqlInterpolatedAsync(
            $"DELETE FROM [Nonces] WHERE [Token] = {nonce.Token}", cancellationToken) == 1;
        telemetry.Complete();
        return removed;
    }

    /// <inheritdoc />
    public async Task<bool> RevokeCertificateAsync(
        CaDbContext context,
        string serialNumber,
        X509RevocationReason reason,
        CancellationToken cancellationToken)
    {
        using var telemetry = MsSqlInstruments.Start("revoke_certificate");
        var revoked = await context.Database.ExecuteSqlInterpolatedAsync(
            $"""
             UPDATE [Certificates] SET [RevocationReason] = {(int)reason}, [RevocationDate] = {DateTimeOffset.UtcNow}
             WHERE [SerialNumber] = {serialNumber}
             """, cancellationToken) == 1;
        telemetry.Complete();
        return revoked;
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<CertificateItemInfo> ReadCertificatePage(
        CaDbContext context,
        string? profileName,
        int page,
        int pageSize,
        bool revokedOnly,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        using var telemetry = MsSqlInstruments.Start("read_certificate_page");
        var query = context.Certificates.AsNoTracking();
        if (revokedOnly)
        {
            query = query.Where(c => c.ProfileName == profileName && c.RevocationReason != null);
        }

        var items = query.OrderBy(c => c.SerialNumber).Skip(checked(page * pageSize)).Take(pageSize)
            .Select(c => new CertificateItemInfo
            {
                SerialNumber = c.SerialNumber,
                DistinguishedName = c.DistinguishedName,
                Issuer = c.Issuer,
                NotBefore = c.NotBefore,
                NotAfter = c.NotAfter,
                Thumbprint = c.Thumbprint,
                RevocationReason = (X509RevocationReason?)c.RevocationReason,
                RevocationDate = c.RevocationDate
            }).AsAsyncEnumerable();
        await foreach (var item in items.WithCancellation(cancellationToken))
        {
            yield return item;
        }
        telemetry.Complete();
    }
}

/// <summary>Opt-in registration of the SQL Server dependency.</summary>
public static class MsSqlStoreExtensions
{
    /// <summary>Selects SQL Server for subsequent relational-store registrations.</summary>
    public static IServiceCollection AddMsSqlStore(this IServiceCollection services)
    {
        services.TryAddSingleton<IRelationalStoreProvider, MsSqlStoreProvider>();
        return services;
    }
}
