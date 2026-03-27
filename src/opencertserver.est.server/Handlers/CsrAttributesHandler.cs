using OpenCertServer.Ca.Utils.X509.Templates;

namespace OpenCertServer.Est.Server.Handlers;

using System.Security.Claims;
using Microsoft.AspNetCore.Http;

public static class CsrAttributesHandler
{
    public static Task<IResult> Handle(
        ClaimsPrincipal? user,
        ICsrTemplateLoader loader)
    {
        return HandleProfile("", user, loader);
    }

    public static async Task<IResult> HandleProfile(
        string? profileName,
        ClaimsPrincipal? user,
        ICsrTemplateLoader loader)
    {
        var template = await loader.GetTemplate(profileName, user).ConfigureAwait(false);
        return new CertificateSigningRequestTemplateResult(template);
    }
}

public class CsrTemplateLoader : ICsrTemplateLoader
{
    public Task<CertificateSigningRequestTemplate> GetTemplate(
        string? profileName = null,
        ClaimsPrincipal? user = null)
    {
        return Task.FromResult(new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null));
    }
}
