using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;

namespace OpenCertServer.Est.Tests;

using System;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Client;
using Configuration;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Server;
using Xunit;

public sealed class EstClientTests : IDisposable
{
    private readonly TestServer _server;

    public EstClientTests()
    {
        using var ecdsa = ECDsa.Create();
        var ecdsaReq = new CertificateRequest("CN=Test Server", ecdsa, HashAlgorithmName.SHA256);
        ecdsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
        var ecdsaCert = ecdsaReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.Date,
            DateTimeOffset.UtcNow.Date.AddYears(1));
        using var rsa = RSA.Create(4096);
        var rsaReq = new CertificateRequest(
            "CN=Test Server",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);
        rsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
        var rsaCert = rsaReq.CreateSelfSigned(DateTimeOffset.UtcNow.Date, DateTimeOffset.UtcNow.Date.AddYears(1));

        var host = CreateHostBuilder(rsaCert, ecdsaCert, rsaCert).Build();
        host.Start();
        _server = host.GetTestServer();
    }

    private static IHostBuilder CreateHostBuilder(
        X509Certificate2 rsaPrivate,
        X509Certificate2 ecdsaPrivate,
        X509Certificate2 webCert)
    {
        var webBuilder = new HostBuilder().ConfigureWebHost(builder =>
        {
            builder.UseTestServer()
                .ConfigureAppConfiguration(b => { b.AddEnvironmentVariables(); });
            var attribute = new AuthorizeAttribute
            {
                AuthenticationSchemes = CertificateAuthenticationDefaults.AuthenticationScheme
            };
            builder.ConfigureServices(sc =>
                {
                    sc.AddRouting();
                    sc.AddAuthorization();
                    sc.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
                        .AddCertificate();
                    sc.AddEstServer(rsaPrivate, ecdsaPrivate);
                    sc.ConfigureOptions<ConfigureCertificateAuthenticationOptions>();
                })
                .Configure(app => app.UseAuthentication().UseAuthorization().UseEstServer(attribute, attribute))
                .ConfigureKestrel(k =>
                {
                    k.AddServerHeader = false;
                    k.ConfigureEndpointDefaults(d => { d.Protocols = HttpProtocols.Http1AndHttp2; });
                    k.ConfigureHttpsDefaults(d =>
                    {
                        d.ServerCertificate = webCert;
                        d.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
                        d.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                        d.AllowAnyClientCertificate();
                        d.CheckCertificateRevocation = false;
                    });
                });
        });

        return webBuilder;
    }

    [Fact]
    public async Task CanRequestEnrollWithRsaKey()
    {
        using var rsa = RSA.Create();
        var client = new EstClient(
            new Uri("https://localhost/"),
            new TestMessageHandler(_server,
                X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
            ));
        var cert = await client.Enroll(
            new X500DistinguishedName("CN=Test, OU=Test Department"),
            rsa,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
            certificate: X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
        );

        Assert.NotNull(cert);
    }

    [Fact]
    public async Task CanRequestEnrollWithEcDsaKey()
    {
        using var ecdsa = ECDsa.Create();
        var client = new EstClient(
            new Uri("https://localhost/"),
            new TestMessageHandler(_server,
                X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
            ));
        var cert = await client.Enroll(
            new X500DistinguishedName("CN=Test, OU=Test Department"),
            ecdsa,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
            certificate: X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
        );

        Assert.NotNull(cert);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _server.Dispose();
    }
}
