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
        var count = 0;
        await foreach (var item in store.GetInventory(index, size, cancellationToken).ConfigureAwait(false))
        {
            count++;
            var profile = await store.GetIssuingProfile(item.Thumbprint, cancellationToken).ConfigureAwait(false);
            if (profile is null || !profiles.Contains(profile))
            {
                continue;
            }

            var serial = Convert.FromHexString(item.SerialNumber);
            var found = false;
            await foreach (var certificate in store.GetCertificatesById(cancellationToken, serial).ConfigureAwait(false))
            {
                using var ownedCertificate = certificate;
                found = true;
                var identity = CertificateIdentity.Read(certificate);
                if (!identity.IsCheckable)
                {
                    continue;
                }

                certificates.Add(new IntuneDeviceCertificate(item.SerialNumber, item.Thumbprint,
                    item.DistinguishedName, profile, identity.IntuneDeviceId, identity.EntraDeviceId,
                    identity.UserPrincipalName, item.NotAfter, item.IsRevoked));
            }

            if (!found)
            {
                throw new InvalidOperationException("A certificate listed in the inventory could not be loaded.");
            }
        }

        return Results.Json(new IntuneDeviceReport(index, size, count == size, certificates),
            IntuneJsonContext.Default.IntuneDeviceReport);
    }
}
