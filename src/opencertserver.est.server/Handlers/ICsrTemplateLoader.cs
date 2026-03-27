using System.Security.Claims;
using OpenCertServer.Ca.Utils.X509.Templates;

namespace OpenCertServer.Est.Server.Handlers;

public interface ICsrTemplateLoader
{
    Task<CertificateSigningRequestTemplate> GetTemplate(string? profileName = null, ClaimsPrincipal? user = null);
}
