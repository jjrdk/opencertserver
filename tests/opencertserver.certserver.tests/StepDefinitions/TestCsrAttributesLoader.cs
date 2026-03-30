namespace OpenCertServer.CertServer.Tests.StepDefinitions;

using System.Security.Claims;
using OpenCertServer.Ca.Utils.X509.Templates;
using OpenCertServer.Est.Server.Handlers;

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
