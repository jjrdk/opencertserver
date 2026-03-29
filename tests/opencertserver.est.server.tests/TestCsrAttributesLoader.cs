using System.Security.Claims;
using OpenCertServer.Ca.Utils.X509.Templates;
using OpenCertServer.Est.Server.Handlers;

namespace OpenCertServer.Est.Tests;

internal class TestCsrAttributesLoader : ICsrTemplateLoader
{
    public async Task<CertificateSigningRequestTemplate> GetTemplate(
        string? profileName,
        ClaimsPrincipal? user)
    {
        await Task.Yield();
        return new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null);
    }
}
