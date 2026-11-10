namespace OpenCertServer.Data;

using OpenCertServer.Data.Entities;
using System.Diagnostics.CodeAnalysis;
using Microsoft.EntityFrameworkCore;

/// <summary>
/// EF Core context for the relational ACME + CA store.
///
/// One table per aggregate (<see cref="AccountEntity"/>, <see cref="OrderEntity"/>, <see cref="NonceEntity"/>,
/// <see cref="ExternalAccountKeyEntity"/>, <see cref="CertificateEntity"/>). Each store creates and disposes its
/// own <see cref="DbContext"/> per operation, so the context is not shared across operations and is not required
/// to be disposable by the consuming code.
/// </summary>
public class CaDbContext : DbContext
{
    /// <summary>Initializes a new instance of the <see cref="CaDbContext"/> class with configured EF options.</summary>
    /// <param name="options">The EF Core options supplied by the selected database provider.</param>
    [RequiresUnreferencedCode("EF Core model building is not trim-safe without the generated compiled model.")]
    [RequiresDynamicCode("EF Core model building requires dynamic code unless a generated compiled model is used.")]
    public CaDbContext(DbContextOptions<CaDbContext> options)
        : base(options)
    {
    }

    /// <summary>ACME accounts (RFC 8555 §7.3).</summary>
    public DbSet<AccountEntity> Accounts => Set<AccountEntity>();

    /// <summary>ACME orders (RFC 8555 §7.1.3).</summary>
    public DbSet<OrderEntity> Orders => Set<OrderEntity>();

    /// <summary>ACME nonces; the token is the primary key.</summary>
    public DbSet<NonceEntity> Nonces => Set<NonceEntity>();

    /// <summary>External account keys, single-use (RFC 8555 §7.3.4).</summary>
    public DbSet<ExternalAccountKeyEntity> ExternalAccountKeys => Set<ExternalAccountKeyEntity>();

    /// <summary>Issued-certificate inventory records.</summary>
    public DbSet<CertificateEntity> Certificates => Set<CertificateEntity>();

    /// <inheritdoc />
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AccountEntity>(e =>
        {
            e.HasKey(x => x.AccountId);
            e.HasIndex(x => x.JwkThumbprint).IsUnique();
            e.HasIndex(x => x.ExternalAccountId);
            e.Property(x => x.Version).IsConcurrencyToken();
        });

        modelBuilder.Entity<OrderEntity>(e =>
        {
            e.HasKey(x => x.OrderId);
            e.HasIndex(x => x.AccountId);
            e.HasIndex(x => x.HasProcessingChallenge);
            e.Property(x => x.Version).IsConcurrencyToken();
        });

        modelBuilder.Entity<NonceEntity>(e => e.HasKey(x => x.Token));

        modelBuilder.Entity<ExternalAccountKeyEntity>(e =>
        {
            e.HasKey(x => x.KeyId);
            e.HasIndex(x => x.BoundAccountId);
            e.Property(x => x.Version).IsConcurrencyToken();
        });

        modelBuilder.Entity<CertificateEntity>(e =>
        {
            e.HasKey(x => x.SerialNumber);
            e.HasIndex(x => x.Thumbprint);
            e.HasIndex(x => x.RevocationReason);
        });
    }
}
