namespace OpenCertServer.Est.Tests.Steps;

using System.Formats.Asn1;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Numerics;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
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
using Ca;
using OpenCertServer.Ca.Server;
using OpenCertServer.Ca.Utils.Ca;
using Ca.Utils;
using Ca.Utils.Pkcs7;
using Ca.Utils.X509;
using Ca.Utils.X509.Templates;
using Client;
using Server;
using Configuration;
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
            options: null,
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

    [When(
        """^a client submits a valid (.+?) certificate signing request \(CSR\) containing a SAN URI using the "(.+?)" certificate profile$""")]
    public async Task WhenAClientSubmitsAValidCsrContainingASanUriUsingTheCertificateProfile(
        string profile,
        string profileName)
    {
        // Mirrors the real-world case of a urn:uuid SAN entry that must survive simpleenroll.
        var sanUri = new Uri($"urn:uuid:{Guid.NewGuid()}");
        _context["requestedSanUri"] = sanUri;
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddUri(sanUri);

        var subjectName = new X500DistinguishedName("CN=Test, OU=Test Department");
        CertificateRequest request;
        X509Certificate2 clientCertificate;
        switch (profile.ToLowerInvariant())
        {
            case "rsa":
                var rsa = RSA.Create();
                clientCertificate = await GetCertificate(rsa);
                request = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
                break;
            case "ecdsa":
                var ecDsa = ECDsa.Create();
                clientCertificate = await GetCertificate(ecDsa);
                request = new CertificateRequest(subjectName, ecDsa, HashAlgorithmName.SHA256);
                break;
            default:
                throw new ArgumentOutOfRangeException(nameof(profile), profile, null);
        }

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment, false));
        request.CertificateExtensions.Add(sanBuilder.Build());

        var (_, cert) = await SubmitSimpleEnrollAsync(request, profile.ToLowerInvariant(), clientCertificate);
        _context["enrolledCertificate"] = cert;
    }

    private async Task<(string? Error, X509Certificate2Collection? Certificates)> SubmitSimpleEnrollAsync(
        CertificateRequest request,
        string profileName,
        X509Certificate2 clientCertificate)
    {
        using var handler = new TestMessageHandler(_server, clientCertificate);
        using var httpClient = new HttpClient(handler);
        var requestMessage = new HttpRequestMessage
        {
            Method = HttpMethod.Post,
            RequestUri = new Uri($"https://localhost/.well-known/est/{profileName}/simpleenroll"),
            Content = new StringContent(request.ToPkcs10Base64(), Encoding.UTF8, "application/pkcs10")
        };
        requestMessage.Headers.TransferEncoding.Add(new TransferCodingHeaderValue("base64"));

        var response = await httpClient.SendAsync(requestMessage);
        if (!response.IsSuccessStatusCode)
        {
            return (await response.Content.ReadAsStringAsync(), null);
        }

        var b64 = await response.Content.ReadAsStringAsync();
        var bytes = b64.Base64DecodeBytes();
        var reader = new AsnReader(bytes, AsnEncodingRules.DER);
        var contentInfo = new CmsContentInfo(reader);
        if (contentInfo.ContentType.Value != Oids.Pkcs7Signed)
        {
            throw new InvalidOperationException("Expected signed data from server");
        }

        reader = new AsnReader(contentInfo.EncodedContent, AsnEncodingRules.DER);
        var signedData = new SignedData(reader);
        return (null, new X509Certificate2Collection(signedData.Certificates ?? []));
    }

    [When(@"^an unauthenticated client submits a valid (.+?) certificate signing request \(CSR\)$")]
    public async Task WhenAnUnauthenticatedClientSubmitsAValidRsaCertificateSigningRequestCsr(string profile)
    {
        using var rsa = RSA.Create();
        var c = await GetCertificate(rsa);
        var client = new EstClient(
            new Uri("https://localhost/"),
            options: null,
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
            options: null,
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
        var client = new EstClient(
            new Uri("https://localhost/"),
            options: null,
            messageHandler: _server.CreateHandler(),
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

    [Then("the issued certificate contains the key usage extension requested in the CSR")]
    public void ThenTheIssuedCertificateContainsTheKeyUsageExtensionRequestedInTheCsr()
    {
        var certificates = Assert.IsType<X509Certificate2Collection>(_context["enrolledCertificate"]);
        var keyUsage = certificates[0].Extensions.OfType<X509KeyUsageExtension>().SingleOrDefault();

        Assert.NotNull(keyUsage);
        Assert.Equal(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.DataEncipherment,
            keyUsage.KeyUsages);
    }

    [Then("the issued certificate contains the SAN URI requested in the CSR")]
    public void ThenTheIssuedCertificateContainsTheSanUriRequestedInTheCsr()
    {
        var certificates = Assert.IsType<X509Certificate2Collection>(_context["enrolledCertificate"]);
        var requestedSanUri = Assert.IsType<Uri>(_context["requestedSanUri"]);

        var sanExtension = certificates[0].Extensions.SingleOrDefault(ext => ext.Oid?.Value == "2.5.29.17");
        Assert.NotNull(sanExtension);

        var sanUris = new GeneralNames(sanExtension.RawData).Names
            .Where(name => name.Type == GeneralName.GeneralNameType.UniformResourceIdentifier)
            .Select(name => ((AsnString)name.Value).Value)
            .ToArray();

        Assert.Contains(requestedSanUri.ToString(), sanUris);
    }

    [When("^the (.+) client uses the previously issued certificate for re-enrollment$")]
    public async Task WhenTheClientUsesThePreviouslyIssuedCertificateForReEnrollment(string keytype)
    {
        var cert = (X509Certificate2Collection)_context["enrolledCertificate"]!;
        var client = new EstClient(
            new Uri("https://localhost/"),
            options: null,
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
                    var (_, c) = await client.ReEnroll(rsa, cert[0]);
                    cert = c;
                    break;
                }
            case "ECDsa":
                {
                    using var ecdsa = ECDsa.Create();
                    ecdsa.ImportSubjectPublicKeyInfo(publicKey, out _);
                    ecdsa.ImportECPrivateKey(privateKey, out _);
                    var (_, c) = await client.ReEnroll(ecdsa, cert[0]);
                    cert = c;
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
        var client = new EstClient(
            new Uri("https://localhost/"),
            options: null,
            messageHandler: _server.CreateHandler(),
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
