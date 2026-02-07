namespace OpenCertServer.Est.Tests.Steps;

using System.Net.Http.Headers;
using System.Numerics;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenCertServer.Ca;
using OpenCertServer.Ca.Server;
using OpenCertServer.Ca.Utils.X509.Templates;
using OpenCertServer.Est.Client;
using OpenCertServer.Est.Server;
using OpenCertServer.Est.Tests.Configuration;
using Reqnroll;
using Xunit;

[Binding]
public class EstServer
{
    private readonly ScenarioContext _context;
    private TestServer _server = null!;

    public EstServer(ScenarioContext context)
    {
        _context = context;
    }

    [Given("a certificate server that complies with EST \\(RFC 7030\\)")]
    public async Task GivenACertificateServerThatCompliesWithEstrfc()
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

        var host = CreateHostBuilder(rsaCert, ecdsaCert, rsaCert).Build();
        await host.StartAsync();
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
            builder.ConfigureServices(sc =>
                {
                    sc.AddCors(o => o.AddPolicy("AllowAll", b =>
                    {
                        b.AllowAnyOrigin()
                            .AllowAnyMethod()
                            .AllowAnyHeader();
                    }));
                    sc.AddRouting();
                    sc.AddAuthorization();
                    sc.AddAuthentication(CertificateAuthenticationDefaults.AuthenticationScheme)
                        .AddCertificate()
                        .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme);
                    sc.AddInMemoryCertificateStore()
                        .AddCertificateAuthority(
                            new CaConfiguration(
                                rsaPrivate,
                                ecdsaPrivate,
                                BigInteger.Zero,
                                TimeSpan.FromDays(90),
                                ["test"],
                                []))
                        .AddEstServer<TestCsrAttributesHandler>()
                        .ConfigureOptions<ConfigureCertificateAuthenticationOptions>()
                        .ConfigureOptions<ConfigureOauthOptions>();
                })
                .Configure(app =>
                    app.UseCors("AllowAll").UseEstServer())
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

    [When(@"a client submits a valid RSA certificate signing request \(CSR\)")]
    public async Task WhenAClientSubmitsAValidRsaCertificateSigningRequestCsr()
    {
        using var rsa = RSA.Create();
        _context["privateKey"] = rsa.ExportRSAPrivateKey();
        _context["publicKey"] = rsa.ExportRSAPublicKey();
        var client = new EstClient(
            new Uri("https://localhost/"),
            new TestMessageHandler(_server,
                X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
            ));
        var (_, cert) = await client.Enroll(
            new X500DistinguishedName("CN=Test, OU=Test Department"),
            rsa,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
            certificate: X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
        );
        _context["enrolledCertificate"] = cert;
    }

    [When(@"a client submits a valid ECDsa certificate signing request \(CSR\)")]
    public async Task WhenAClientSubmitsAValidEcDsaCertificateSigningRequestCsr()
    {
        using var rsa = ECDsa.Create();
        _context["privateKey"] = rsa.ExportECPrivateKey();
        _context["publicKey"] = rsa.ExportSubjectPublicKeyInfo();
        var client = new EstClient(
            new Uri("https://localhost/"),
            new TestMessageHandler(_server,
                X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
            ));
        var (_, cert) = await client.Enroll(
            new X500DistinguishedName("CN=Test, OU=Test Department"),
            rsa,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
            certificate: X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
        );
        _context["enrolledCertificate"] = cert;
    }

    [When(@"an unauthenticated client submits a valid RSA certificate signing request \(CSR\)")]
    public async Task WhenAnUnauthenticatedClientSubmitsAValidRsaCertificateSigningRequestCsr()
    {
        using var rsa = RSA.Create();
        var client = new EstClient(
            new Uri("https://localhost/"),
            _server.CreateHandler());
        var (error, cert) = await client.Enroll(
            new X500DistinguishedName("CN=Test, OU=Test Department"),
            rsa,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
            certificate: X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
        );
        _context["errorMessage"] = error;
        _context["enrolledCertificate"] = cert;
    }

    [When(@"an unauthenticated client submits a valid ECDsa certificate signing request \(CSR\)")]
    public async Task WhenAnUnauthenticatedClientSubmitsAValidEcDsaCertificateSigningRequestCsr()
    {
        using var rsa = ECDsa.Create();
        var client = new EstClient(
            new Uri("https://localhost/"),
            _server.CreateHandler());
        var (error, cert) = await client.Enroll(
            new X500DistinguishedName("CN=Test, OU=Test Department"),
            rsa,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
            certificate: X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
        );
        _context["errorMessage"] = error;
        _context["enrolledCertificate"] = cert;
    }

    [When("a client submits an invalid CSR")]
    public async Task WhenAClientSubmitsAnInvalidCsr()
    {
        using var handler = _server.CreateHandler();
        using var rsa = ECDsa.Create();
        var client = new EstClient(
            new Uri("https://localhost/"),
            new TestMessageHandler(_server,
                X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
            ));
        var (error, cert) = await client.Enroll(
            new X500DistinguishedName(""),
            rsa,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
            certificate: X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
        );
        _context["errorMessage"] = error;
        _context["enrolledCertificate"] = cert;
    }

    [When("an authenticated client requests the server attributes")]
    public async Task WhenAnAuthenticatedClientRequestsTheServerAttributes()
    {
        var client = new EstClient(new Uri("https://localhost/"), _server.CreateHandler());
        var attributes = await client.GetCsrAttributes(
            new AuthenticationHeaderValue("Bearer", "valid-jwt"));

        Assert.NotNull(attributes);
        _context["csrAttributes"] = attributes;
    }

    [When("the server returns a signed certificate")]
    [Then("the server returns a signed certificate")]
    public void ThenTheServerReturnsASignedCertificate()
    {
        Assert.NotNull(_context["enrolledCertificate"]);
    }

    [When("the (.+) client uses the previously issued certificate for re-enrollment")]
    public async Task WhenTheClientUsesThePreviouslyIssuedCertificateForReEnrollment(string keytype)
    {
        var cert = (X509Certificate2Collection)_context["enrolledCertificate"]!;
        var client = new EstClient(
            new Uri("https://localhost/"),
            new TestMessageHandler(_server,
                X509CertificateLoader.LoadPkcs12FromFile("test.pfx", null)
            ));
        var privateKey = (byte[])_context["privateKey"]!;
        var publicKey = (byte[])_context["publicKey"]!;
        switch (keytype)
        {
            case "RSA":
            {
                using var rsa = RSA.Create();
                rsa.ImportRSAPublicKey(publicKey, out _);
                rsa.ImportRSAPrivateKey(privateKey, out _);
                cert = await client.ReEnroll(rsa, cert[0]);
                break;
            }
            case "ECDsa":
            {
                using var ecdsa = ECDsa.Create();
                ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                ecdsa.ImportECPrivateKey(privateKey, out _);
                cert = await client.ReEnroll(ecdsa, cert[0]);
                break;
            }
            default:
                throw new InvalidOperationException($"Unknown key type: {keytype}");
        }

        _context["enrolledCertificate"] = cert;
    }

    [Then("the server should return an error message indicating the reason for the failure")]
    public void ThenTheServerShouldReturnAnErrorMessageIndicatingTheReasonForTheFailure()
    {
        Assert.NotNull(_context["errorMessage"]);
        Assert.Null(_context["enrolledCertificate"]);
    }

    [When("a client requests the CA certificates")]
    public async Task WhenAClientRequestsTheCaCertificates()
    {
        var client = new EstClient(new Uri("https://localhost/"), _server.CreateHandler());
        var certs = await client.ServerCertificates();
        _context["certificates"] = certs;
    }

    [Then("the server should return the CA certificates in the correct format")]
    public void ThenTheServerShouldReturnTheCaCertificatesInTheCorrectFormat()
    {
        Assert.IsType<X509Certificate2Collection>(_context["certificates"]);
        Assert.Equal(2, ((X509Certificate2Collection)_context["certificates"]).Count);
    }

    [Then("the server should return the server attributes in the correct format")]
    public void ThenTheServerShouldReturnTheServerAttributesInTheCorrectFormat()
    {
        Assert.IsType<CertificateSigningRequestTemplate>(_context["csrAttributes"]);
    }
}
