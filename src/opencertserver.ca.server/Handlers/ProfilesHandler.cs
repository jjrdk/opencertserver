namespace OpenCertServer.Ca.Server.Handlers;

using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using OpenCertServer.Ca.Utils.Ca;

public static class ProfilesHandler
{
    /// <summary>
    /// <c>GET /ca/profiles</c>: lists the names of the profiles the CA supports, one per line.
    /// This is the discovery endpoint an RA or ACME server uses to learn which profiles it may offer
    /// and can call again to pick up a later-updated profile set. Only names are returned - the
    /// profile material (keys, chains, validity) never crosses the wire.
    /// </summary>
    public static async Task<IResult> Handle(
        ClaimsPrincipal user,
        ICertificateAuthority ca,
        CancellationToken cancellationToken)
    {
        var names = await ca.GetSupportedProfiles(cancellationToken).ConfigureAwait(false);
        var text = string.Join(Environment.NewLine, names);
        return Results.Text(text, "text/plain");
    }
}
