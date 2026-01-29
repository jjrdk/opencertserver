namespace OpenCertServer.CertServer;

using System.Security.Claims;
using OpenCertServer.Ca.Utils.X509.Templates;

internal class CsrAttributesHandler : Est.Server.Handlers.CsrAttributesHandler
{
    public override async Task<CertificateSigningRequestTemplate> GetTemplate(ClaimsPrincipal user)
    {
        await Task.Yield();
        return new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null);
    }
}
