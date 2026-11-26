namespace OpenCertServer.Contrib.Intune;

using Microsoft.AspNetCore.Http;
using OpenCertServer.Ca.Utils.Ca;

/// <summary>Certificate and device identifiers read from the stored certificate.</summary>
public sealed record IntuneDeviceCertificate(
    string SerialNumber, string Thumbprint, string Subject, string Profile,
    string? IntuneDeviceId, string? EntraDeviceId, string? UserPrincipalName,
    DateTimeOffset NotAfter, bool IsRevoked);

/// <summary>A page of the certificate inventory, filtered to configured Intune profiles.</summary>
public sealed record IntuneDeviceReport(int Page, int PageSize, bool HasMore, IReadOnlyList<IntuneDeviceCertificate> Certificates);

internal static class IntuneDeviceReportHandler
{
    public static async Task<IResult> Handle(
        IStoreCertificates store, IntuneOptions options, int? page, int? pageSize, CancellationToken cancellationToken)
    {
        var index = page ?? 0;
        var size = pageSize ?? 100;
        if (index < 0 || size is < 1 or > 100 || index > int.MaxValue / size)
        {
            return Results.BadRequest("page must be non-negative and pageSize must be between 1 and 100.");
        }

        var profiles = options.SyncProfiles.ToHashSet(StringComparer.Ordinal);
        var certificates = new List<IntuneDeviceCertificate>();
        var inventory = new List<CertificateItemInfo>();
        await foreach (var item in store.GetInventory(index, size, cancellationToken).ConfigureAwait(false))
        {
            inventory.Add(item);
        }

        var issuingProfiles = await store.GetIssuingProfiles(
            inventory.Select(item => item.Thumbprint), cancellationToken).ConfigureAwait(false);
        var selected = inventory.Where(item =>
            issuingProfiles.TryGetValue(item.Thumbprint, out var profile)
            && profile is not null && profiles.Contains(profile)).ToList();
        var identities = new Dictionary<string, CertificateIdentity>(StringComparer.OrdinalIgnoreCase);
        if (selected.Count > 0)
        {
            await foreach (var certificate in store.GetCertificatesByThumbprint(
                selected.Select(item => item.Thumbprint.AsMemory()), cancellationToken).ConfigureAwait(false))
            {
                using var ownedCertificate = certificate;
                identities[certificate.Thumbprint] = CertificateIdentity.Read(certificate);
            }
        }

        foreach (var item in selected)
        {
            if (!identities.TryGetValue(item.Thumbprint, out var identity))
            {
                throw new InvalidOperationException("A certificate listed in the inventory could not be loaded.");
            }
            if (identity.IsCheckable)
            {
                certificates.Add(new IntuneDeviceCertificate(item.SerialNumber, item.Thumbprint,
                    item.DistinguishedName, issuingProfiles[item.Thumbprint]!, identity.IntuneDeviceId,
                    identity.EntraDeviceId, identity.UserPrincipalName, item.NotAfter, item.IsRevoked));
            }
        }

        return Results.Json(new IntuneDeviceReport(index, size, inventory.Count == size, certificates),
            IntuneJsonContext.Default.IntuneDeviceReport);
    }
}
