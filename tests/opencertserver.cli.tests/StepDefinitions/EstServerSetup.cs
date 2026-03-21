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

namespace opencertserver.cli.tests.StepDefinitions;

public partial class OpenCertServerCliStepDefinitions
{
    private TestServer _server = null!;
    private X509Certificate2? _estRootCertificate;

    [Given("an EST server")]
    public async Task GivenAnEstServer()
    {
        _estRootCertificate = CreateServerCertificate();

        var host = new HostBuilder().ConfigureWebHost(builder =>
        {
            builder
                .UseTestServer()
                .UseUrls("http://localhost")
                .ConfigureAppConfiguration(c => c.AddEnvironmentVariables())
                .ConfigureServices(ConfigureEstServices)
                .Configure(ConfigureEstApp);
        }).Build();
        host.Start();
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
            .AddEstServer<TestCsrAttributesHandler>()
            .AddSingleton(sp => sp.GetRequiredService<ICertificateAuthority>().GetRootCertificates())
            .AddRouting()
            .AddAuthorization()
            .AddAuthentication()
            .AddCertificate();
    }

    private static X509Certificate2 CreateServerCertificate()
    {
        using var rsa = RSA.Create(4096);
        var request = new CertificateRequest("CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
        var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        return cert; //.CopyWithPrivateKey(rsa);
    }

    public void Dispose()
    {
        _server?.Dispose();
        _estRootCertificate?.Dispose();

        GC.SuppressFinalize(this);
    }
}

