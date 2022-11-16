namespace OpenCertServer.Est.Tests
{
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

            _server = new TestServer(CreateHostBuilder(rsaCert, ecdsaCert, rsaCert));
        }

        private static IWebHostBuilder CreateHostBuilder(
            X509Certificate2 rsaPrivate,
            X509Certificate2 ecdsaPrivate,
            X509Certificate2 webCert)
        {
            var webBuilder = new WebHostBuilder().UseKestrel()
                .ConfigureAppConfiguration(b => { b.AddEnvironmentVariables(); });

            webBuilder.ConfigureServices(
                    sc =>
                    {
                        sc.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme);
                        sc.AddEstServer(rsaPrivate, ecdsaPrivate);
                        sc.ConfigureOptions<ConfigureCertificateAuthenticationOptions>();
                    })
                .Configure(app => app.UseEstServer())
                .ConfigureKestrel(
                k =>
                {
                    k.AddServerHeader = false;
                    k.ConfigureEndpointDefaults(
                        d =>
                        {
                            d.Protocols = HttpProtocols.Http1AndHttp2;
                        });
                    k.ConfigureHttpsDefaults(
                        d =>
                        {
                            d.ServerCertificate = webCert;
                            d.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
                            d.SslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13;
                            d.AllowAnyClientCertificate();
                            d.CheckCertificateRevocation = false;
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
                new TestMessageHandler(_server, new X509Certificate2(X509Certificate.CreateFromCertFile("test.pfx"))));
            var cert = await client.Enroll(
                    new X500DistinguishedName("CN=Test, OU=Test Department"),
                    rsa,
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
                    certificate: new X509Certificate2(X509Certificate.CreateFromCertFile("test.pfx")))
                .ConfigureAwait(false);

            Assert.NotNull(cert);
        }

        [Fact]
        public async Task CanRequestEnrollWithEcDsaKey()
        {
            using var ecdsa = ECDsa.Create();
            var client = new EstClient(
                new Uri("https://localhost/"),
                new TestMessageHandler(_server, new X509Certificate2(X509Certificate.CreateFromCertFile("test.pfx"))));
            var cert = await client.Enroll(
                    new X500DistinguishedName("CN=Test, OU=Test Department"),
                    ecdsa!,
                    X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
                    certificate: new X509Certificate2(X509Certificate.CreateFromCertFile("test.pfx")))
                .ConfigureAwait(false);

            Assert.NotNull(cert);
        }

        /// <inheritdoc />
        public void Dispose()
        {
            GC.SuppressFinalize(this);
            _server?.Dispose();
        }
    }
}
