namespace OpenCertServer.Est.Tests;

using System.Security.Claims;
using OpenCertServer.Est.Server.Handlers;

internal class TestCsrAttributesLoader : ICsrTemplateLoader
{
    public async Task<CsrAttributesResponse> GetTemplate(
        string? profileName,
        ClaimsPrincipal? user,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        return CsrAttributesResponse.Unavailable();
    }
}
