using System.Security.Claims;
using OpenCertServer.Ca.Utils.X509.Templates;
using OpenCertServer.Est.Server.Handlers;

namespace OpenCertServer.Est.Tests;

internal class TestCsrAttributesHandler : CsrAttributesHandler
{
    public override async Task<CertificateSigningRequestTemplate> GetTemplate(ClaimsPrincipal user)
    {
        await Task.Yield();
        return new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null);
    }
}
