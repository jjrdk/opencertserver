using System.Security.Claims;
using System.Threading.Tasks;
using OpenCertServer.Est.Server.Handlers;
using OpenCertServer.Ca.Utils.X509.Templates;

namespace opencertserver.cli.tests.StepDefinitions;

internal class TestCsrAttributesHandler : CsrAttributesHandler
{
    public override async Task<CertificateSigningRequestTemplate> GetTemplate(ClaimsPrincipal user)
    {
        await Task.Yield();
        return new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null);
    }
}


