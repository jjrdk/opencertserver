namespace opencertserver.cli.tests.StepDefinitions;

using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using OpenCertServer.Est.Server.Handlers;
using OpenCertServer.Ca.Utils.X509.Templates;

internal class TestCsrAttributesLoader : ICsrTemplateLoader
{
    public async Task<CertificateSigningRequestTemplate> GetTemplate(
        string? profileName,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        return new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null);
    }
}
