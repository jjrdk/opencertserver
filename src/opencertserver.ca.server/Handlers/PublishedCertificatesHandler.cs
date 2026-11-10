using System.Linq;
using System.Threading;
using System.Threading.Tasks;

namespace OpenCertServer.Ca.Server.Handlers;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenCertServer.Ca.Utils.Ca;
using System.Security.Claims;

public static class PublishedCertificatesHandler
{
    /// <summary>
    /// <c>GET /ca/published</c>: publishes the full certificate chain a client needs to reach the
    /// root from the issuing CA (issuing CA plus root, and any published intermediates). This is the
    /// endpoint a remote SCEP (RFC 8894) or EST (RFC 9092) peer that cannot host the CA core uses for
    /// its GetCACert chain and renewal anchors, so the CA stays authoritative for what is published.
    /// It is authenticated the same way as <c>POST /ca/csr</c> so a remote RA/RA-proxy cannot
    /// enumerate the published chain without the CA trusting its identity.
    /// </summary>
    /// <param name="user">The authenticated caller (a CA admin role or the CA itself).</param>
    /// <param name="ca">The certificate authority service.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public static Task<IResult> Handle(
        ClaimsPrincipal user,
        ICertificateAuthority ca,
        CancellationToken cancellationToken)
    {
        return HandleProfile(null, ca, cancellationToken);
    }

    /// <summary>
    /// <c>GET /ca/{profile}/published</c>: the published chain for a named profile.
    /// </summary>
    /// <param name="user">The authenticated caller (a CA admin role or the CA itself).</param>
    /// <param name="ca">The certificate authority service.</param>
    /// <param name="profileName">The profile name.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    public static Task<IResult> HandleProfile(
        ClaimsPrincipal user,
        ICertificateAuthority ca,
        [FromRoute] string profileName,
        CancellationToken cancellationToken)
    {
        return HandleProfile(profileName, ca, cancellationToken);
    }

    private static async Task<IResult> HandleProfile(
        string? profileName,
        ICertificateAuthority ca,
        CancellationToken cancellationToken)
    {
        var certificates = await ca.GetPublishedCertificates(profileName, cancellationToken)
            .ConfigureAwait(false);

        if (certificates.Count == 0)
        {
            return Results.NotFound();
        }

        var pem = string.Join("\n", certificates.Select(x => x.ExportCertificatePem()));
        return Results.Text(pem, Constants.PemMimeType);
    }
}
