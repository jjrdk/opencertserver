namespace OpenCertServer.Data;

using System.Security.Cryptography.X509Certificates;
using Microsoft.EntityFrameworkCore;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>Database-specific operations supplied by an independently referenced provider.</summary>
public interface IRelationalStoreProvider
{
    /// <summary>Configures the EF provider, migrations assembly and any provider-specific model options.</summary>
    void Configure(DbContextOptionsBuilder options, string connectionString);

    /// <summary>Identifies a unique-constraint violation without treating other database failures as conflicts.</summary>
    bool IsUniqueViolation(DbUpdateException exception);

    /// <summary>Inserts a nonce atomically; an existing token must be left unchanged.</summary>
    Task SaveNonceAsync(CaDbContext context, Nonce nonce, CancellationToken cancellationToken);

    /// <summary>Atomically consumes a nonce, returning true for exactly one caller.</summary>
    Task<bool> TryRemoveNonceAsync(CaDbContext context, Nonce nonce, CancellationToken cancellationToken);

    /// <summary>Records revocation and returns whether the certificate exists.</summary>
    Task<bool> RevokeCertificateAsync(
        CaDbContext context,
        string serialNumber,
        X509RevocationReason reason,
        CancellationToken cancellationToken);

    /// <summary>Streams a zero-based, serial-ordered certificate page, optionally restricted to revocations.</summary>
    IAsyncEnumerable<CertificateItemInfo> ReadCertificatePage(
        CaDbContext context,
        string? profileName,
        int page,
        int pageSize,
        bool revokedOnly,
        CancellationToken cancellationToken);
}
