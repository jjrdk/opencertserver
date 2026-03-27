namespace opencertserver.cli.tests.StepDefinitions;

using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Ca.Server;
using OpenCertServer.Ca.Utils.Ca;
using OpenCertServer.Ca.Utils.Ocsp;
using OpenCertServer.Est.Server;
using Reqnroll;

public partial class OpenCertServerCliStepDefinitions
{
    private TestServer? _server;

    [Given("an EST server")]
    public async Task GivenAnEstServer()
    {
        var host = new HostBuilder().ConfigureWebHost(builder =>
        {
            builder
                .UseTestServer()
                .UseUrls("http://localhost")
                .ConfigureAppConfiguration(c => c.AddEnvironmentVariables())
                .ConfigureServices(ConfigureEstServices)
                .Configure(ConfigureEstApp);
        }).Build();
        await host.StartAsync();
        _server = host.GetTestServer();
    }

    private static void ConfigureEstApp(IApplicationBuilder app)
    {
        var allowAll = new AuthorizationPolicyBuilder().RequireAssertion(_ => true).Build();
        app.UseEstServer(allowAll, allowAll, allowAll, allowAll);
    }

    private static void ConfigureEstServices(IServiceCollection services)
    {
        services
            .AddSingleton<IResponderId>(new ResponderIdByKey("cli-est"u8.ToArray()))
            .AddInMemoryCertificateStore()
            .AddSelfSignedCertificateAuthority(new X500DistinguishedName("CN=OpenCertServer CLI EST"),
                ocspUrls: ["test"])
            .AddEstServer<TestCsrAttributesLoader>()
            .AddSingleton(sp => sp.GetRequiredService<ICertificateAuthority>().GetRootCertificates())
            .AddRouting()
            .AddAuthorization()
            .AddAuthentication()
            .AddCertificate();
    }

    public void Dispose()
    {
        _server?.Dispose();
        GC.SuppressFinalize(this);
    }
}

