namespace OpenCertServer.Acme.Yarp.Tests.StepDefinitions;

using Acme.AspNetClient.Certes;
using Acme.AspNetClient.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Reqnroll;
using Xunit;

[Binding]
public partial class ChallengeApprovalSteps : IDisposable
{
    private TestServer? _server;
    private int _responseCode;
    private string? _responseBody;

    [Given(@"a middleware that serves the known token ""(.+)"" with response ""(.+)""")]
    public void GivenAMiddlewareThatServesTheKnownTokenWithResponse(string token, string response)
    {
        var persistence = Substitute.For<IPersistenceService>();
        persistence.GetPersistedChallenges().Returns([
            new ChallengeDto(token, response, ["alpha.example.com", "beta.example.com"])
        ]);

        var host = new HostBuilder().ConfigureWebHost(webBuilder =>
               {
                   webBuilder
                            .UseTestServer()
                            .ConfigureServices(services =>
                               {
                                   services.AddSingleton(persistence);
                               })
                            .Configure(app =>
                               {
                                   app.UseMiddleware<AcmeChallengeApprovalMiddleware>();
                                   app.Run(async context =>
                                         {
                                             context.Response.StatusCode = 404;
                                             await context.Response.WriteAsync("Not found").ConfigureAwait(false);
                                         });
                               })
                            .ConfigureLogging(l => l.AddFilter((_, level) => false));
               });

        var built = host.Build();
        built.Start();
        _server = built.GetTestServer();
    }

    [When(@"I request the ACME challenge path for token ""(.+)""")]
    public async Task WhenIRequestTheAcmeChallengePathForToken(string token)
    {
        var client = _server!.CreateClient();
        var response = await client.GetAsync($"/.well-known/acme-challenge/{token}").ConfigureAwait(false);

        _responseCode = (int)response.StatusCode;
        _responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
    }

    [Then(@"the approval response status code should be (\d+)")]
    public void ThenTheApprovalResponseStatusCodeShouldBe(int expected)
    {
        Assert.Equal(expected, _responseCode);
    }

    [Then(@"the approval response body should be ""(.+)""")]
    public void ThenTheApprovalResponseBodyShouldBe(string expected)
    {
        Assert.Equal(expected, _responseBody);
    }

    public void Dispose()
    {
        _server?.Dispose();
    }
}
