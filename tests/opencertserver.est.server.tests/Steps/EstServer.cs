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
using OpenCertServer.Ca.Utils.Ca;
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

    private async Task<X509Certificate2> GetCertificate<TKey>(TKey key) where TKey : AsymmetricAlgorithm
    {
        var ca = _server.Services.GetRequiredService<ICertificateAuthority>();
        var subjectName = new X500DistinguishedName("CN=test");
        var profile = key is RSA ? "rsa" : "ecdsa";
        var csr = key switch
        {
            RSA rsa => new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss),
            ECDsa ecdsa => new CertificateRequest(subjectName, ecdsa, HashAlgorithmName.SHA256),
            _ => throw new ArgumentOutOfRangeException(nameof(key), key, null)
        };
        var response = await ca.SignCertificateRequest(csr, profile);
        return response switch
        {
            SignCertificateResponse.Success success => success.Certificate,
            _ => throw new Exception($"Certificate error: {response}")
        };
    }

    [Given("a certificate server that complies with EST \\(RFC 7030\\)")]
    public async Task GivenACertificateServerThatCompliesWithEstRfc()
    {
        using var ecdsa = ECDsa.Create();
        var ecdsaReq = new CertificateRequest("CN=ECDsa Test Server", ecdsa, HashAlgorithmName.SHA256);
        ecdsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 5, false));
        ecdsaReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(ecdsaReq.PublicKey, false));
        ecdsaReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        var ecdsaCert = ecdsaReq.CreateSelfSigned(
            DateTimeOffset.UtcNow.Date,
            DateTimeOffset.UtcNow.Date.AddYears(1));
        using var rsa = RSA.Create();
        var rsaReq = new CertificateRequest(
            "CN=RSA Test Server",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);
        rsaReq.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        rsaReq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(rsaReq.PublicKey, false));
        rsaReq.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, false));
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
                                new CaProfileSet(
                                    "rsa",
                                    new CaProfile
                                    {
                                        CertificateChain =
                                            [X509Certificate2.CreateFromPem(rsaPrivate.ExportCertificatePem())],
                                        Name = "rsa",
                                        CertificateValidity = TimeSpan.FromDays(90),
                                        CrlNumber = BigInteger.Zero,
                                        PrivateKey = rsaPrivate.GetRSAPrivateKey()!
                                    },
                                    new CaProfile
                                    {
                                        CertificateChain =
                                            [X509Certificate2.CreateFromPem(ecdsaPrivate.ExportCertificatePem())],
                                        Name = "ecdsa",
                                        CertificateValidity = TimeSpan.FromDays(90),
                                        CrlNumber = BigInteger.Zero,
                                        PrivateKey = ecdsaPrivate.GetECDsaPrivateKey()!
                                    }
                                ),
                                ["test"],
                                [],
                                []))
                        .AddEstServer<TestCsrAttributesLoader>()
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

    [When(
        """^a client submits a valid (.+?) certificate signing request \(CSR\) using the "(.+?)" certificate profile$""")]
    public async Task WhenAClientSubmitsAValidCertificateSigningRequestCsrUsingTheCertificateProfile(
        string profile,
        string profileName)
    {
        AsymmetricAlgorithm key = null!;
        switch (profile.ToLowerInvariant())
        {
            case "rsa":
                var rsa = RSA.Create();
                key = rsa;
                _context["privateKey"] = rsa.ExportRSAPrivateKey();
                _context["publicKey"] = key.ExportSubjectPublicKeyInfo();
                _context["certificate"] = await GetCertificate(rsa);
                break;
            case "ecdsa":
                var ecDsa = ECDsa.Create();
                key = ecDsa;
                _context["privateKey"] = ecDsa.ExportECPrivateKey();
                _context["publicKey"] = key.ExportSubjectPublicKeyInfo();
                _context["certificate"] = await GetCertificate(ecDsa);
                break;
        }

        var client = new EstClient(
            new Uri("https://localhost/"),
            profileName: profile.ToLowerInvariant(),
            messageHandler: new TestMessageHandler(_server, _context["certificate"] as X509Certificate2));
        var (_, cert) = await client.Enroll(
            new X500DistinguishedName("CN=Test, OU=Test Department"),
            key,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
            certificate: _context["certificate"] as X509Certificate2
        );
        _context["enrolledCertificate"] = cert;
    }

    [When(@"^an unauthenticated client submits a valid (.+?) certificate signing request \(CSR\)$")]
    public async Task WhenAnUnauthenticatedClientSubmitsAValidRsaCertificateSigningRequestCsr(string profile)
    {
        using var rsa = RSA.Create();
        var c = await GetCertificate(rsa);
        var client = new EstClient(
            new Uri("https://localhost/"),
            messageHandler: _server.CreateHandler(),
            profileName: profile);
        var (error, cert) = await client.Enroll(
            new X500DistinguishedName("CN=Test, OU=Test Department"),
            rsa,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
            certificate: c
        );
        _context["errorMessage"] = error;
        _context["enrolledCertificate"] = cert;
    }

    [When("a client submits an invalid CSR")]
    public async Task WhenAClientSubmitsAnInvalidCsr()
    {
        using var handler = _server.CreateHandler();
        using var rsa = ECDsa.Create();
        var c = await GetCertificate(rsa);
        var client = new EstClient(
            new Uri("https://localhost/"),
            messageHandler: new TestMessageHandler(_server, c));
        var (error, cert) = await client.Enroll(
            new X500DistinguishedName(""),
            rsa,
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
            certificate: c
        );
        _context["errorMessage"] = error;
        _context["enrolledCertificate"] = cert;
    }

    [When("^an authenticated client requests the server attributes for the (.+?) certificate profile$")]
    public async Task WhenAnAuthenticatedClientRequestsTheServerAttributes(string profile)
    {
        var client = new EstClient(new Uri("https://localhost/"), messageHandler: _server.CreateHandler(),
            profileName: profile);
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

    [When("^the (.+) client uses the previously issued certificate for re-enrollment$")]
    public async Task WhenTheClientUsesThePreviouslyIssuedCertificateForReEnrollment(string keytype)
    {
        var cert = (X509Certificate2Collection)_context["enrolledCertificate"]!;
        var client = new EstClient(
            new Uri("https://localhost/"),
            profileName: keytype.ToLowerInvariant(),
            messageHandler: new TestMessageHandler(_server));
        var privateKey = (byte[])_context["privateKey"]!;
        var publicKey = (byte[])_context["publicKey"]!;
        switch (keytype)
        {
            case "RSA":
            {
                using var rsa = RSA.Create();
                rsa.ImportSubjectPublicKeyInfo(publicKey, out _);
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

    [When("^a client requests the CA certificates for the \"(.+?)\" certificate profile$")]
    public async Task WhenAClientRequestsTheCaCertificates(string profileName)
    {
        var client = new EstClient(new Uri("https://localhost/"), messageHandler: _server.CreateHandler(),
            profileName: profileName);
        var certs = await client.ServerCertificates();
        _context["certificates"] = certs;
    }

    [Then("the server should return the CA certificates in the correct format")]
    public void ThenTheServerShouldReturnTheCaCertificatesInTheCorrectFormat()
    {
        Assert.IsType<X509Certificate2Collection>(_context["certificates"]);
        Assert.Single((X509Certificate2Collection)_context["certificates"]);
    }

    [Then("the server should return the server attributes in the correct format")]
    public void ThenTheServerShouldReturnTheServerAttributesInTheCorrectFormat()
    {
        Assert.IsType<CertificateSigningRequestTemplate>(_context["csrAttributes"]);
    }
}
