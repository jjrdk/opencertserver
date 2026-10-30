using System.Text.Json;

namespace OpenCertServer.Data.Stores;

using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Acme.Abstractions.Model;
using OpenCertServer.Acme.Abstractions.Storage;
using OpenCertServer.Data.Entities;
using OpenCertServer.Data.Serialization;

/// <summary>
/// Relational <see cref="IStoreAccounts"/> using the configured EF provider. Each operation opens a scope and disposes its
/// own <see cref="CaDbContext"/>. The full <see cref="Account"/> is stored as a JSON payload preserving get-only
/// identity fields; the scalar <see cref="AccountEntity.JwkThumbprint"/> / <see cref="AccountEntity.ExternalAccountId"/>
/// columns back the lookup paths.
/// </summary>
public sealed class RelationalAccountStore : IStoreAccounts
{
    /// <summary>The scope factory used to create a scoped <see cref="CaDbContext"/> per operation.</summary>
    private readonly IServiceScopeFactory _scopeFactory;

    /// <summary>Initializes a new instance of the <see cref="RelationalAccountStore"/> class.</summary>
    /// <param name="scopeFactory">The DI <see cref="IServiceScopeFactory"/>.</param>
    public RelationalAccountStore(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    /// <inheritdoc />
    public async Task SaveAccount(Account account, CancellationToken cancellationToken)
    {
        var entity = new AccountEntity
        {
            AccountId = account.AccountId ??
                throw new ArgumentException("Account is missing its identifier.", nameof(account)),
            JwkThumbprint = Convert.ToBase64String(account.Jwk.ComputeJwkThumbprint()),
            ExternalAccountId = account.ExternalAccountId,
            Status = account.Status.ToString(),
            Payload = JsonSerializer.Serialize(account,
                DataSerializerContext.Default.Account), // JsonMapper.SaveAccount(account),
            Version = checked(account.Version + 1),
        };

        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        if (account.Version == 0)
        {
            db.Accounts.Add(entity);
        }
        else
        {
            db.Accounts.Update(entity).Property(e => e.Version).OriginalValue = account.Version;
        }

        await db.SaveAggregateAsync(scope.ServiceProvider.GetRequiredService<IRelationalStoreProvider>(), cancellationToken);
        account.Version = entity.Version;
    }

    /// <inheritdoc />
    public async Task<Account?> LoadAccount(string accountId, CancellationToken cancellationToken)
    {
        var id = accountId;
        var ct = cancellationToken;
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var entity = await db.Accounts.AsNoTrackingWithIdentityResolution()
            .FirstOrDefaultAsync(e => e.AccountId == id, ct);
        return FromEntity(entity);
    }

    /// <inheritdoc />
    public async Task<Account?> FindAccount(
        Microsoft.IdentityModel.Tokens.JsonWebKey jwk,
        CancellationToken cancellationToken)
    {
        var ct = cancellationToken;
        var thumbprint = Convert.ToBase64String(jwk.ComputeJwkThumbprint());
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var entity = await db.Accounts.AsNoTrackingWithIdentityResolution()
            .FirstOrDefaultAsync(e => e.JwkThumbprint == thumbprint, ct);
        return FromEntity(entity);
    }

    private static Account? FromEntity(AccountEntity? entity)
    {
        if (entity is null)
        {
            return null;
        }

        var account = JsonSerializer.Deserialize(entity.Payload, DataSerializerContext.Default.Account)!;
        account.Version = entity.Version;
        return account;
    }
}
