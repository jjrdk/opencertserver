using System.Numerics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Ca;

namespace OpenCertServer.Est.Tests;

using Microsoft.AspNetCore.Builder;
using System;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
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

public abstract class WebServerTests : IDisposable
{
    protected readonly TestServer Server;

    protected WebServerTests()
    {
        using var ecdsa = ECDsa.Create();
        var ecdsaReq = new CertificateRequest("CN=Test Server", ecdsa, HashAlgorithmName.SHA256);
        ecdsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, false));
        ecdsaReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(ecdsaReq.PublicKey, false));
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
        rsaReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rsaReq.PublicKey, false));
        var rsaCert = rsaReq.CreateSelfSigned(DateTimeOffset.UtcNow.Date, DateTimeOffset.UtcNow.Date.AddYears(1));
        var rsaPublic = X509CertificateLoader.LoadCertificate(ecdsaCert.GetRawCertData());

        var host = CreateHostBuilder(rsaCert, ecdsaCert, rsaPublic).Build();
        host.Start();
        Server = host.GetTestServer();
    }

    private static IHostBuilder CreateHostBuilder(
        X509Certificate2 rsaPrivate,
        X509Certificate2 ecdsaPrivate,
        X509Certificate2? webCert)
    {
        var webBuilder = new HostBuilder().ConfigureWebHost(builder =>
        {
            builder
                .UseTestServer()
                .ConfigureAppConfiguration(b => { b.AddEnvironmentVariables(); });

            builder.ConfigureServices(sc =>
                {
                    sc.AddRouting()
                        .AddAuthorization()
                        .AddSingleton<IStoreCertificates>(new InMemoryCertificateStore())
                        .AddEstServer(new CaConfiguration(rsaPrivate, ecdsaPrivate, BigInteger.Zero, TimeSpan.FromDays(90), ["test"], []))
                        .ConfigureOptions<ConfigureCertificateAuthenticationOptions>()
                        .AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
                        .AddCertificate(CertificateAuthenticationDefaults.AuthenticationScheme);
                })
                .Configure(app =>
                {
                    var attribute = new AuthorizeAttribute
                    {
                        AuthenticationSchemes = CertificateAuthenticationDefaults.AuthenticationScheme
                    };
                    app.UseAuthentication().UseAuthorization().UseEstServer(attribute, attribute);
                });
            builder.ConfigureKestrel(k =>
            {
                k.AddServerHeader = false;
                k.ConfigureEndpointDefaults(d => { d.Protocols = HttpProtocols.Http1AndHttp2; });
                k.ConfigureHttpsDefaults(d =>
                {
                    if (webCert != null)
                    {
                        d.ServerCertificate = webCert;
                    }

                    d.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
                    d.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                    d.AllowAnyClientCertificate();
                    d.CheckCertificateRevocation = false;
                });
            });
        });

        return webBuilder;
    }

    protected static CertificateRequest CreateCertificateRequest(RSA rsa)
    {
        var req = new CertificateRequest(
            "CN=Test, OU=Test Department",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pss);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                false));

        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new("1.3.6.1.5.5.7.3.8")], true));

        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req;
    }

    protected static CertificateRequest CreateCertificateRequest(ECDsa ecdsa)
    {
        var req = new CertificateRequest("CN=Test, OU=Test Department", ecdsa, HashAlgorithmName.SHA256);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation,
                false));

        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new("1.3.6.1.5.5.7.3.8")], true));

        req.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(req.PublicKey, false));
        return req;
    }

    [Fact]
    public async Task CanReceiveServerCertificates()
    {
        var client = Server.CreateClient();
        var response = await client.GetAsync("https://localhost/.well-known/est/cacert");
        var bytes = await response.Content.ReadAsStringAsync();
        var certificateCollection = new X509Certificate2Collection();
        certificateCollection.ImportFromPem(bytes);

        Assert.Equal(2, certificateCollection.Count);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        GC.SuppressFinalize(this);
        Server.Dispose();
    }
}
