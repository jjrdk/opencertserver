using OpenCertServer.Est.Server.Response;

namespace OpenCertServer.Est.Server.Handlers;

using System.Security.Claims;
/// <summary>
/// Defines the default implementation of the <see cref="ICsrTemplateLoader"/> interface.
/// </summary>
public class CsrTemplateLoader : ICsrTemplateLoader
{
    /// <inheritdoc />
    public Task<CsrAttributesResponse> GetTemplate(
        string? profileName = null,
        ClaimsPrincipal? user = null,
        CancellationToken cancellationToken = default)
    {
        return Task.FromResult(CsrAttributesResponse.Unavailable());
    }
}
