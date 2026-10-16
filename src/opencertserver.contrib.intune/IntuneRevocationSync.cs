namespace OpenCertServer.Contrib.Intune;

using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>One certificate the sync revoked, or would revoke in a dry run.</summary>
public sealed record SyncRevocation(string SerialNumber, string Subject, string Reason);

/// <summary>One certificate the sync could not judge - Graph did not answer for sure.</summary>
public sealed record SyncUnknown(string SerialNumber, string Subject, string Reason);

/// <summary>
/// What a sync run did. <see cref="Aborted"/> is set when the run stopped before
/// revoking anything: too many hits (see <see cref="IntuneOptions.MaxRevocationsPerSync"/>)
/// or a run already in progress.
/// </summary>
public sealed record SyncReport(
    bool DryRun,
    int Checked,
    IReadOnlyList<SyncRevocation> Revoked,
    IReadOnlyList<SyncUnknown> Unknown,
    string? Aborted = null,
    bool AlreadyRunning = false);

/// <summary>
/// Intune never tells the CA when a user is disabled or a device is retired; without
/// this, their certificates stay valid until they expire. The sync walks the CA's
/// inventory, asks Graph about the user (UPN from the SAN), the Intune device
/// (<c>IntuneDeviceId://</c> URI) and the Entra device (GUID common name), and revokes
/// what is gone or disabled. It is an operation, not a scheduler - whoever runs it
/// decides how often.
///
/// Fail-safe by design: Graph unreachable, throttled or answering unexpectedly means
/// "unknown", and unknown is never revoked. An outage at Microsoft must not lock
/// everyone out.
/// </summary>
public sealed partial class IntuneRevocationSync
{
    private readonly IIntuneClient _intune;
    private readonly IStoreCertificates _store;
    private readonly ICertificateAuthority _ca;
    private readonly IntuneOptions _options;
    private readonly ILogger<IntuneRevocationSync> _logger;
    private readonly TimeProvider _time;
    private readonly SemaphoreSlim _running = new(1, 1);

    public IntuneRevocationSync(
        IIntuneClient intune,
        IStoreCertificates store,
        ICertificateAuthority ca,
        IntuneOptions options,
        ILogger<IntuneRevocationSync> logger,
        TimeProvider? time = null)
    {
        _intune = intune;
        _store = store;
        _ca = ca;
        _options = options;
        _logger = logger;
        _time = time ?? TimeProvider.System;
    }

    /// <summary>True while a run is in progress.</summary>
    public bool IsRunning => _running.CurrentCount == 0;

    public async Task<SyncReport> Run(bool dryRun, CancellationToken cancellationToken)
    {
        if (!await _running.WaitAsync(TimeSpan.Zero, cancellationToken).ConfigureAwait(false))
        {
            return new SyncReport(dryRun, 0, [], [], "A sync is already running.", AlreadyRunning: true);
        }

        try
        {
            return await RunLocked(dryRun, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _running.Release();
        }
    }

    private async Task<SyncReport> RunLocked(bool dryRun, CancellationToken cancellationToken)
    {
        var now = _time.GetUtcNow();
        var hits = new List<(CertificateItemInfo Item, string Reason)>();
        var unknown = new List<SyncUnknown>();
        var checkedCount = 0;

        await foreach (var item in Inventory(cancellationToken).ConfigureAwait(false))
        {
            if (item.IsRevoked || item.NotAfter <= now.UtcDateTime)
            {
                continue;
            }

            var certificate = await LoadCertificate(item, cancellationToken).ConfigureAwait(false);
            if (certificate is null)
            {
                continue;
            }

            var identity = CertificateIdentity.Read(certificate);
            if (!identity.IsCheckable)
            {
                continue;
            }

            checkedCount++;
            try
            {
                var reason = await Judge(identity, cancellationToken).ConfigureAwait(false);
                if (reason is not null)
                {
                    hits.Add((item, reason));
                }
            }
            catch (GraphUnavailableException ex)
            {
                LogUnknown(_logger, item.SerialNumber, item.DistinguishedName, ex.Message);
                unknown.Add(new SyncUnknown(item.SerialNumber, item.DistinguishedName, ex.Message));
            }
        }

        if (hits.Count > _options.MaxRevocationsPerSync)
        {
            var message =
                $"{hits.Count} certificates would be revoked, more than the limit of {_options.MaxRevocationsPerSync} - "
                + "nothing revoked. Check the tenant and the app permissions, or raise Scep:Intune:MaxRevocationsPerSync.";
            LogAborted(_logger, hits.Count, _options.MaxRevocationsPerSync);
            return new SyncReport(dryRun, checkedCount, [], unknown, message);
        }

        var revoked = new List<SyncRevocation>(hits.Count);
        foreach (var (item, reason) in hits)
        {
            if (!dryRun)
            {
                var done = await _ca.RevokeCertificate(item.SerialNumber, X509RevocationReason.CessationOfOperation, cancellationToken)
                    .ConfigureAwait(false);
                if (!done)
                {
                    unknown.Add(new SyncUnknown(item.SerialNumber, item.DistinguishedName, "The CA did not revoke it."));
                    continue;
                }

                LogRevoked(_logger, item.SerialNumber, item.DistinguishedName, reason);
            }

            revoked.Add(new SyncRevocation(item.SerialNumber, item.DistinguishedName, reason));
        }

        LogFinished(_logger, dryRun, checkedCount, revoked.Count, unknown.Count);
        return new SyncReport(dryRun, checkedCount, revoked, unknown);
    }

    /// <summary>Why the certificate should go, or null when everything behind it is still there and enabled.</summary>
    private async Task<string?> Judge(CertificateIdentity identity, CancellationToken cancellationToken)
    {
        if (identity.UserPrincipalName is { } upn)
        {
            switch (await _intune.GetUserState(upn, cancellationToken).ConfigureAwait(false))
            {
                case DirectoryState.Missing:
                    return "The user no longer exists in Entra.";
                case DirectoryState.Disabled:
                    return "The user is disabled in Entra.";
            }
        }

        if (identity.IntuneDeviceId is { } deviceId && Guid.TryParse(deviceId, out _))
        {
            if (await _intune.GetManagedDeviceState(deviceId, cancellationToken).ConfigureAwait(false) == DirectoryState.Missing)
            {
                return "The device is no longer managed by Intune (retired, wiped or deleted).";
            }
        }

        if (identity.UserPrincipalName is null && identity.EntraDeviceId is { } entraDeviceId)
        {
            switch (await _intune.GetEntraDeviceState(entraDeviceId, cancellationToken).ConfigureAwait(false))
            {
                case DirectoryState.Missing:
                    return "The device no longer exists in Entra.";
                case DirectoryState.Disabled:
                    return "The device is disabled in Entra.";
            }
        }

        return null;
    }

    private async IAsyncEnumerable<CertificateItemInfo> Inventory(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        const int pageSize = 100;
        for (var page = 0;; page++)
        {
            var count = 0;
            await foreach (var item in _store.GetInventory(page, pageSize, cancellationToken).ConfigureAwait(false))
            {
                count++;
                yield return item;
            }

            if (count < pageSize)
            {
                yield break;
            }
        }
    }

    // By serial number, not by thumbprint: the stores key their items by serial, and the
    // in-memory store's GetCertificatesByThumbprint compares thumbprints against those keys
    // and finds nothing (seen 16.10.2026 while building this).
    private async Task<X509Certificate2?> LoadCertificate(CertificateItemInfo item, CancellationToken cancellationToken)
    {
        byte[] serial;
        try
        {
            serial = Convert.FromHexString(item.SerialNumber);
        }
        catch (FormatException)
        {
            return null;
        }

        await foreach (var certificate in _store.GetCertificatesById(cancellationToken, serial).ConfigureAwait(false))
        {
            return certificate;
        }

        return null;
    }

    [LoggerMessage(LogLevel.Warning, "Intune sync: {Serial} ({Subject}) could not be judged, stays valid: {Reason}")]
    private static partial void LogUnknown(ILogger logger, string serial, string subject, string reason);

    [LoggerMessage(LogLevel.Information, "Intune sync: revoked {Serial} ({Subject}): {Reason}")]
    private static partial void LogRevoked(ILogger logger, string serial, string subject, string reason);

    [LoggerMessage(LogLevel.Error, "Intune sync aborted: {Hits} certificates would be revoked, limit is {Limit} - nothing revoked")]
    private static partial void LogAborted(ILogger logger, int hits, int limit);

    [LoggerMessage(LogLevel.Information, "Intune sync finished (dry run: {DryRun}): {CheckedCount} checked, {Revoked} revoked, {Unknown} unknown")]
    private static partial void LogFinished(ILogger logger, bool dryRun, int checkedCount, int revoked, int unknown);
}
