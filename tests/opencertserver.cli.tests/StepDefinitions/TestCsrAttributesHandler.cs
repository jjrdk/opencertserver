namespace opencertserver.cli.tests.StepDefinitions;

using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
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
