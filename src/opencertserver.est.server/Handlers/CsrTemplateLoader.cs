namespace OpenCertServer.Est.Server.Handlers;

using System.Security.Claims;
using OpenCertServer.Ca.Utils.X509.Templates;

/// <summary>
/// Defines the default implementation of the <see cref="ICsrTemplateLoader"/> interface.
/// </summary>
public class CsrTemplateLoader : ICsrTemplateLoader
{
    /// <inheritdoc />
    public Task<CertificateSigningRequestTemplate> GetTemplate(
        string? profileName = null,
        ClaimsPrincipal? user = null,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(new CertificateSigningRequestTemplate(subject: null, subjectPkInfo: null));
    }
}
