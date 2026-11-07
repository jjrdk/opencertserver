namespace OpenCertServer.Data.Stores;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Data.Entities;

/// <summary>Relational <see cref="IStoreCertificates"/> using the configured EF provider, one scope per operation.</summary>
public sealed class RelationalCertificateStore : IStoreCertificates
{
    /// <summary>The scope factory used to create a scoped <see cref="CaDbContext"/> per operation.</summary>
    private readonly IServiceScopeFactory _scopeFactory;

    /// <summary>Initializes a new instance of the <see cref="RelationalCertificateStore"/> class.</summary>
    /// <param name="scopeFactory">The DI <see cref="IServiceScopeFactory"/>.</param>
    public RelationalCertificateStore(IServiceScopeFactory scopeFactory)
    {
        _scopeFactory = scopeFactory;
    }

    /// <inheritdoc />
    public Task AddCertificate(X509Certificate2 certificate, CancellationToken cancellationToken = default) =>
        AddCertificate(certificate, null!, cancellationToken);

    /// <inheritdoc />
    public async Task AddCertificate(
        X509Certificate2 certificate,
        string issuingProfile,
        CancellationToken cancellationToken = default)
    {
        using var telemetry = DataInstruments.Start("certificate.add");
        var item = CertificateItem.FromX509Certificate2(certificate);
        var entity = new CertificateEntity
        {
            SerialNumber = item.SerialNumber,
            ProfileName = issuingProfile,
            DistinguishedName = item.DistinguishedName,
            Issuer = item.Issuer,
            NotBefore = item.NotBefore.ToUniversalTime(),
            NotAfter = item.NotAfter.ToUniversalTime(),
            Thumbprint = item.Thumbprint,
            PublicKeyPem = item.PublicKeyPem,
        };

        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        await db.Certificates.AddAsync(entity, cancellationToken);
        await db.SaveChangesAsync(cancellationToken);
        telemetry.Complete();
    }

    /// <inheritdoc />
    public async Task<string?> GetIssuingProfile(string thumbprint, CancellationToken cancellationToken = default)
    {
        using var telemetry = DataInstruments.Start("certificate.get_issuing_profile");
        var key = thumbprint.ToUpperInvariant();
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var entity = await db.Certificates.AsNoTrackingWithIdentityResolution()
            .FirstOrDefaultAsync(c => c.Thumbprint == key, cancellationToken);
        var profileName = entity?.ProfileName;
        telemetry.Complete();
        return profileName;
    }

    /// <inheritdoc />
    public async Task<bool> RemoveCertificate(string serialNumber, X509RevocationReason reason, CancellationToken cancellationToken = default)
    {
        using var telemetry = DataInstruments.Start("certificate.revoke");
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var revoked = await scope.ServiceProvider.GetRequiredService<IRelationalStoreProvider>()
            .RevokeCertificateAsync(db, serialNumber, reason, cancellationToken);
        telemetry.Complete();
        return revoked;
    }

    /// <inheritdoc />
    public IAsyncEnumerable<CertificateItemInfo> GetRevocationList(
        string? profileName,
        int page = 0,
        int pageSize = 100,
        CancellationToken cancellationToken = default) =>
        ReadPage(profileName, page, pageSize, revokedOnly: true, cancellationToken);

    /// <inheritdoc />
    public async Task<(CertId, CertificateStatus, RevokedInfo?)> GetCertificateStatus(
        CertId certId,
        CancellationToken cancellationToken = default)
    {
        using var telemetry = DataInstruments.Start("certificate.get_status");
        var key = Convert.ToHexString(certId.SerialNumber);
        var ct = cancellationToken;
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var entity = await db.Certificates.AsNoTrackingWithIdentityResolution().FirstOrDefaultAsync(e => e.SerialNumber == key, ct);
        if (entity is null)
        {
            telemetry.Complete();
            return (certId, CertificateStatus.Unknown, null);
        }
        if (entity.RevocationReason is null)
        {
            telemetry.Complete();
            return (certId, CertificateStatus.Good, null);
        }
        var date = entity.RevocationDate!.Value;
        telemetry.Complete();
        return (certId, CertificateStatus.Revoked, new RevokedInfo(date, (X509RevocationReason)entity.RevocationReason.Value));
    }

    /// <inheritdoc />
    public IAsyncEnumerable<CertificateItemInfo> GetInventory(
        int page = 0,
        int pageSize = 100,
        CancellationToken cancellationToken = default) =>
        ReadPage(null, page, pageSize, revokedOnly: false, cancellationToken);

    private async IAsyncEnumerable<CertificateItemInfo> ReadPage(
        string? profileName,
        int page, int pageSize, bool revokedOnly,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        using var telemetry = DataInstruments.Start(revokedOnly
            ? "certificate.read_revocation_page"
            : "certificate.read_inventory_page");
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var provider = scope.ServiceProvider.GetRequiredService<IRelationalStoreProvider>();
        await foreach (var item in provider.ReadCertificatePage(db, profileName, page, pageSize, revokedOnly, cancellationToken))
        {
            yield return item;
        }
        telemetry.Complete();
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<X509Certificate2> GetCertificatesById(
        [EnumeratorCancellation] CancellationToken cancellationToken,
        params IEnumerable<ReadOnlyMemory<byte>> ids)
    {
        using var telemetry = DataInstruments.Start("certificate.get_by_id");
        var keys = ids.Select(i => Convert.ToHexString(i.Span)).ToList();
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var entities = db.Certificates.AsNoTrackingWithIdentityResolution()
            .Where(e => keys.Contains(e.SerialNumber))
            .OrderBy(e => e.SerialNumber)
            .AsAsyncEnumerable();
        await foreach (var e in entities.WithCancellation(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return X509Certificate2.CreateFromPem(e.PublicKeyPem);
        }
        telemetry.Complete();
    }

    /// <inheritdoc />
    public async IAsyncEnumerable<X509Certificate2> GetCertificatesByThumbprint(
        IEnumerable<ReadOnlyMemory<char>> thumbprint,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        using var telemetry = DataInstruments.Start("certificate.get_by_thumbprint");
        var set = thumbprint.Select(t => t.ToString().ToUpperInvariant()).ToList();
        using var scope = _scopeFactory.CreateScope();
        await using var db = scope.ServiceProvider.GetRequiredService<CaDbContext>();
        var entities = db.Certificates.AsNoTrackingWithIdentityResolution()
            .Where(e => set.Contains(e.Thumbprint))
            .OrderBy(e => e.SerialNumber)
            .AsAsyncEnumerable();
        await foreach (var e in entities.WithCancellation(cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return X509Certificate2.CreateFromPem(e.PublicKeyPem);
        }
        telemetry.Complete();
    }
}
