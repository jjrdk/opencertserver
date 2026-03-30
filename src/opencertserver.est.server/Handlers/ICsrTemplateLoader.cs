namespace OpenCertServer.Est.Server.Handlers;

using System.Security.Claims;
using OpenCertServer.Ca.Utils.X509.Templates;

/// <summary>
/// Defines the interface for loading Certificate Signing Request templates.
/// </summary>
public interface ICsrTemplateLoader
{
    /// <summary>
    /// Gets a Certificate Signing Request template based on the specified profile and user.
    /// </summary>
    /// <param name="profileName">The profile name to use for selecting the template. If null, the default template will be used.</param>
    /// <param name="user">The user for whom the template is being requested. If null, the template will be selected based on the profile only.</param>
    /// <param name="cancellationToken">The cancellation token to use for the operation.</param>
    /// <returns>The selected Certificate Signing Request template.</returns>
    Task<CertificateSigningRequestTemplate> GetTemplate(string? profileName = null, ClaimsPrincipal? user = null, CancellationToken cancellationToken = default);
}
