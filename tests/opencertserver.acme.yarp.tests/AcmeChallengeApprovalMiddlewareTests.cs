namespace OpenCertServer.Acme.Yarp.Tests;

using System.Net;
using System.Threading.Tasks;
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
using Xunit;

/// <summary>
/// Covers §4.5 "HTTP-01 challenge works per-route via the existing middleware" through a live
/// <see cref="TestServer"/> pipeline that mirrors <c>UseAcmeClient()</c>: a known token resolves to
/// 200 with its key-authorization body; an unknown token yields 410 Gone. The middleware is
/// host-agnostic, so it serves challenges for every route unchanged.
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
        persistence.GetPersistedChallenges().Returns(new[]
             {
             new ChallengeDto(Token, Response, new[] { "alpha.example.com", "beta.example.com" })
             });

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
                            await context.Response.WriteAsync("Not found");
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
    public async Task KnownTokenResolvesForAnyRoute()
    {
        var response = await _client.GetAsync($"/.well-known/acme-challenge/{Token}", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Response, await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task UnknownTokenYields410Gone()
    {
        var response = await _client.GetAsync("/.well-known/acme-challenge/doesnotexist", TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Gone, response.StatusCode);
    }
}
