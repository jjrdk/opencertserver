namespace OpenCertServer.Acme.AspNetClient.Tests;

using System.Net;
using System.Threading.Tasks;
using Certes;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using NSubstitute;
using Persistence;
using Xunit;

/// <summary>
/// Covers §4.5 of the YARP reverse-proxy ACME compatibility plan: the existing
/// <see cref="AcmeChallengeApprovalMiddleware"/> resolves a known challenge token (200) and
/// rejects an unknown token with 410 Gone. The middleware is host-agnostic, so it works per-route
/// without change.
/// </summary>
public sealed class AcmeChallengeApprovalMiddlewareTests : IDisposable
{
    private const string Token = "tok-abc";
    private const string Response = "tok-abc-keyauthz-response";

    private readonly IHost _host;
    private readonly HttpClient _client;

    public AcmeChallengeApprovalMiddlewareTests()
    {
        var persistence = Substitute.For<IPersistenceService>();
        persistence.GetPersistedChallenges().Returns([
            new ChallengeDto(Token, Response, ["alpha.example.com"])
        ]);

        var builder = new HostBuilder().ConfigureWebHost(webBuilder =>
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

        _host = builder.Build();
        _host.Start();
        var server = _host.GetTestServer();
        _client = server.CreateClient();
    }

    public void Dispose()
    {
        _host.Dispose();
        _client.Dispose();
    }

    [Fact]
    public async Task KnownTokenReturns200AndTokenBody()
    {
        var response =
            await _client.GetAsync($"/.well-known/acme-challenge/{Token}", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Response, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task UnknownTokenReturns410Gone()
    {
        var response = await _client.GetAsync("/.well-known/acme-challenge/does-not-exist", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
    }
}
