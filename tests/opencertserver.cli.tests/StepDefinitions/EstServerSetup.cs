namespace opencertserver.cli.tests.StepDefinitions;

using System;
using System.Security.Cryptography;
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

    private HttpMessageHandler CreateReEnrollmentTlsHandler(string certificatePath, string keyPath)
    {
        using var certificate = X509CertificateLoader.LoadCertificateFromFile(certificatePath);
        using AsymmetricAlgorithm key = certificate.GetKeyAlgorithm() == "1.2.840.113549.1.1.1"
            ? RSA.Create()
            : ECDsa.Create();
        key.ImportFromPem(File.ReadAllText(keyPath));
        var identity = key switch
        {
            RSA rsa => certificate.CopyWithPrivateKey(rsa),
            ECDsa ecdsa => certificate.CopyWithPrivateKey(ecdsa),
            _ => throw new NotSupportedException()
        };
        return new CliEnrollmentTlsHandler(_server!, identity);
    }

    private sealed class CliEnrollmentTlsHandler(TestServer server, X509Certificate2 certificate) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Xunit.Assert.False(request.Headers.Contains("X-Client-Cert"));
            Xunit.Assert.True(certificate.HasPrivateKey);
            var context = await server.SendAsync(async context =>
            {
                context.Connection.ClientCertificate = certificate;
                context.Request.Scheme = "https";
                context.Request.Method = request.Method.Method;
                context.Request.Path = request.RequestUri!.AbsolutePath;
                foreach (var header in request.Headers)
                {
                    context.Request.Headers[header.Key] = header.Value.ToArray();
                }

                if (request.Content != null)
                {
                    context.Request.Body = await request.Content.ReadAsStreamAsync(cancellationToken);
                    foreach (var header in request.Content.Headers)
                    {
                        context.Request.Headers[header.Key] = header.Value.ToArray();
                    }
                }
            }, cancellationToken);
            var content = new StreamContent(context.Response.Body);
            var response = new HttpResponseMessage((System.Net.HttpStatusCode)context.Response.StatusCode)
                { Content = content, RequestMessage = request };
            foreach (var header in context.Response.Headers)
            {
                if (!response.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray()))
                {
                    content.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
                }
            }

            return response;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                certificate.Dispose();
            }

            base.Dispose(disposing);
        }
    }

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
        await host.StartAsync().ConfigureAwait(false);
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
