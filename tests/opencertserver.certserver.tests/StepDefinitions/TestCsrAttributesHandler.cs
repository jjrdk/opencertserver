using System.Security.Claims;
using OpenCertServer.Ca.Utils.X509.Templates;

namespace OpenCertServer.CertServer.Tests.StepDefinitions;

internal class TestCsrAttributesHandler : Est.Server.Handlers.CsrAttributesHandler
{
    public override async Task<CertificateSigningRequestTemplate> GetTemplate(ClaimsPrincipal user)
    {
        await Task.Yield();
        return new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null);
    }
}
