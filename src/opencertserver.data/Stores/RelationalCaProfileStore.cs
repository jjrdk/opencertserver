namespace OpenCertServer.Data.Stores;

using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Data.Entities;
using OpenCertServer.Data.Serialization;

/// <summary>
/// Relational <see cref="IStoreCaProfiles"/> using the configured EF provider, one scope per operation.
/// The interface is read-only; this store additionally exposes <see cref="SaveProfileAsync"/> and
/// <see cref="DeleteProfileAsync"/> so a deployment can seed and maintain the profile table.
/// </summary>
public sealed class RelationalCaProfileStore : IStoreCaProfiles
{
    /// <summary>The scope factory used to create a scoped <see cref="CaDbContext"/> per operation.</summary>
    private readonly IServiceScopeFactory _scopeFactory;

    /// <summary>Initializes a new instance of the <see cref="RelationalCaProfileStore"/> class.</summary>
    /// <param name="scopeFactory">The DI <see cref="IServiceScopeFactory"/>.</param>
    public RelationalCaProfileStore(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    /// <inheritdoc />
    public async Task<CaProfile> GetProfile(string? name, CancellationToken cancellationToken = default)
    {
        using var telemetry = DataInstruments.Start(name is null
            ? "ca_profile.get_default"
            : "ca_profile.get_by_name");
        var ct = cancellationToken;
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        if (name is not null)
        {
            var named = await db.CaProfiles.AsNoTracking().FirstOrDefaultAsync(e => e.Name == name, ct);
            if (named is not null)
            {
                var profile = CaProfileSerializer.Deserialize(named.Payload);
                telemetry.Complete();
                return profile;
            }
        }

        var defaultEntity = await db.CaProfiles.AsNoTracking().FirstOrDefaultAsync(e => e.IsDefault, ct);
        if (defaultEntity is null)
        {
            telemetry.Complete();
            throw new InvalidOperationException("No default CA profile is configured.");
        }

        var defaultProfile = CaProfileSerializer.Deserialize(defaultEntity.Payload);
        telemetry.Complete();
        return defaultProfile;
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<CaProfile> GetProfiles(
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var telemetry = DataInstruments.Start("ca_profile.get_all");
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var entities = db.CaProfiles.AsNoTracking().OrderBy(e => e.Name).AsAsyncEnumerable();
        await foreach (var entity in entities.WithCancellation(cancellationToken))
        {
            yield return CaProfileSerializer.Deserialize(entity.Payload);
        }

        telemetry.Complete();
    }

    /// <summary>
    /// Creates or replaces the profile named by <see cref="CaProfile.Name"/>, optionally marking it the default
    /// profile. Replacing a non-default profile with <c>isDefault</c> set does not demote the existing default.
    /// </summary>
    public async Task SaveProfileAsync(CaProfile profile, bool isDefault, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(profile);
        using var telemetry = DataInstruments.Start("ca_profile.save");
        var entity = new CaProfileEntity
        {
            Name = profile.Name,
            IsDefault = isDefault,
            Payload = CaProfileSerializer.Serialize(profile),
        };
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var existing = await db.CaProfiles.FirstOrDefaultAsync(e => e.Name == entity.Name, cancellationToken);
        if (existing is null)
        {
            db.CaProfiles.Add(entity);
        }
        else
        {
            existing.IsDefault = entity.IsDefault;
            existing.Payload = entity.Payload;
        }

        await db.SaveChangesAsync(cancellationToken);
        telemetry.Complete();
    }

    /// <summary>Deletes the profile with the given name, returning whether a row was removed.</summary>
    public async Task<bool> DeleteProfileAsync(string name, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(name);
        using var telemetry = DataInstruments.Start("ca_profile.delete");
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var entity = await db.CaProfiles.FirstOrDefaultAsync(e => e.Name == name, cancellationToken);
        if (entity is null)
        {
            telemetry.Complete();
            return false;
        }

        db.CaProfiles.Remove(entity);
        await db.SaveChangesAsync(cancellationToken);
        telemetry.Complete();
        return true;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        // The store is a long-lived singleton holding only a scope factory; each operation disposes its own scope.
    }
}
