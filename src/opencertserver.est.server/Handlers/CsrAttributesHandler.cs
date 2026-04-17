using OpenCertServer.Est.Server.Response;

namespace OpenCertServer.Est.Server.Handlers;

using System.Security.Claims;
using Microsoft.AspNetCore.Http;

public static class CsrAttributesHandler
{
    public static Task<IResult> Handle(
        ClaimsPrincipal? user,
        ICsrTemplateLoader loader,
        CancellationToken cancellationToken = default)
    {
        return HandleProfile("", user, loader, cancellationToken);
    }

    public static async Task<IResult> HandleProfile(
        string? profileName,
        ClaimsPrincipal? user,
        ICsrTemplateLoader loader,
        CancellationToken cancellationToken = default)
    {
        var attributes = await loader.GetTemplate(profileName, user, cancellationToken).ConfigureAwait(false);
        return new CertificateSigningRequestTemplateResult(attributes);
    }
}
